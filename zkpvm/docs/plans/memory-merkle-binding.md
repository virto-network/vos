# Phase A design: in-circuit Merkle binding of the RAM boundary (`initial_root`/`final_root`)

Implements Phase A of `trustless-chain-verification-roadmap.md`: replace the
unbound `memory_commitment = blake3(flat image)` metadata with Merkle roots of
the RAM that are **bound in-circuit**, so chain verification becomes sound for
memory. Decisions inherited from the roadmap (not re-litigated here): approach
A (Merkle memory), tree keyed by **page address** (not hashed keys),
**4096-byte pages**, **blake2b** (the existing compression AIR), no PCS change.

This is v2, after a five-lens adversarial review of v1. The review's breaks
and the resulting changes are folded in throughout; §7 lists the negative
tests each one demands.

## 0. The page Merkle tree (host-side spec)

- Address space: the full `u32` range → page index = `addr >> 12`, **20 bits**
  → a complete binary tree of **depth 20**, leaves = pages.
  **Soundness premise (explicit): tree depth D < log2(p) = 31.** The §1
  no-range-check argument for internal indices depends on it; a compile-time
  assert guards the page-size constant.
- Hash = standard **blake2b-256** (param block `digest_length = 32`, i.e.
  `h[0] ^= 0x0101_0020`; no length padding beyond the zero-filled final block;
  output = first 32 bytes of the little-endian final state) over tag-prefixed
  messages, with **domain tags as full 128-byte first blocks** so page bytes
  stay block-aligned:
  - `H_leaf(page[4096]) = Blake2b256(TAG_LEAF_BLOCK ‖ page)` — 33 blocks, but
    block 0 is page-independent, so `H_AFTER_LEAF_TAG = compress(IV_param,
    TAG_LEAF_BLOCK, t=128, f=false)` is a **precomputed constant** and only
    the **32 page blocks** are proven (block k: `t = 128·(k+2)`; final block:
    `t = 4224`, `f = true`).
  - `H_node(l, r) = Blake2b256(TAG_NODE_BLOCK ‖ l ‖ r)` — **one proven
    compression per node**: `compress(H_AFTER_NODE_TAG, l ‖ r ‖ 0^64, t=192,
    f=true)`, with `H_AFTER_NODE_TAG` precomputed. The 64 pad bytes enter the
    lookup tuple as **literal field constants**, never witness columns.
  - Tags: distinct 128-byte constants (ASCII label, zero-padded). A host↔AIR
    equivalence test pins one known page leaf + one known node against a
    standard blake2b-256 library.
- Default (absent / never-touched / past-image-end) page = **all-zero bytes**;
  `DEFAULT[20] = H_leaf(0^4096)`, `DEFAULT[ℓ] = H_node(DEFAULT[ℓ+1],
  DEFAULT[ℓ+1])` — used only host-side (in-AIR, untouched subtrees are
  covered by witness siblings pinned by root equality, the cipher-clerk
  `BatchProof` argument).
- Host module `page_merkle`: full-image root; **the single shared
  touched-page enumeration** (absorbing `collect_initial_bytes`'s
  byte-granular union over steps + all five precompile mem-op families — one
  source of truth used by BOTH the ledger entry builder and the page-image /
  frontier builder); entering/exit page images via `segment::replay_writes`;
  the multiproof witness (frontier sibling hashes per witness slot of the
  radix trie of listed page indices).
- **The listed page set is never empty**: the prover always lists
  `max(touched_pages, {page 0})`. A segment with no RAM access lists page 0
  read-only (before == after). This makes every chip below unconditionally
  active and removes any verifier-side empty/non-empty branch — there is no
  prover-controlled signal selecting a degenerate path (review: the
  empty-path branch was attackable however it was signalled).

## 1. The boundary multiproof, in-AIR (cipher-clerk `BatchProof` design)

Per segment, prove ONE shared schedule over the radix trie of the listed page
set, evaluated twice: once over entering ("before") leaves → `initial_root`,
once over exit ("after") leaves → `final_root`. Soundness of witness reuse:
chain continuity pins `initial_root_i == final_root_{i-1}` (and segment 0
against the verifier-supplied expected root, §4), which pins every consulted
witness, so the after-pass recomputation with the same witnesses yields the
true `final_root` (cipher-clerk `merkle.rs` verify/update argument).

The trie is enforced by **logup balance** on an internal relation
(`MerkleNode`): tuples `(level[1], index[1], hash_before[32], hash_after[32])`
= 66 limbs. **`index` is a single M31 limb** (2^20 − 1 < p), NOT byte limbs —
logup tuples match per-limb, and a byte-limbed index breaks the degree-1
child arithmetic on doubling carries (review BREAK: honest proofs would
reject). The leaf producer emits `index` as the degree-1 recomposition of its
range-pinned byte decomposition (§3.2), so all produced leaf indices are
< 2^20.

- Leaf rows (MemoryPageChip) **produce** `(20, page_idx, leaf_b, leaf_a)`, +1
  each.
- Merge rows (MemoryMerkleChip) **consume** their two children and **produce**
  the parent: for each child slot, either consume `(ℓ+1, 2n+b, h_b, h_a)`
  with −1 (computed child) or take a **witness** sibling occupying **one
  physical column set referenced by both passes' H_node lookups** — the
  witness-reuse rule is structural, not a separate equality (review: two
  independent sibling columns would allow a clean untouched-subtree forgery;
  this is the single most load-bearing wiring rule in the chip, gate-tested).
  Produce `(ℓ, n, H_node(...before...), H_node(...after...))` with +1, both
  parent hashes pinned by `Blake2bCompression` lookups (§3.1).
- MemoryRootBoundaryChip (§3.4) consumes exactly one `(0, 0, root_b, root_a)`.

Why balance enforces the schedule:
- every production must be consumed exactly once; the only external sink is
  the single root consumption at `(0,0)`;
- merge-row `level` is **range-constrained to [0,19]** (5-bit decomposition +
  two forbidden-range products), so `level+1` never wraps and levels strictly
  decrease upward — no cycles, and no merge row can consume the level-0 root
  tuple (defense-in-depth; even unconstrained, a wrap chain cannot close in a
  bounded trace);
- internal indices are deliberately **NOT range-checked**: children `2n`,
  `2n+1` are degree-1 from the row's `n`; a wrapped/huge `n` produces a node
  unreachable from `(0,0)` by the doubling paths (all root-reachable indices
  at level ℓ are integers < 2^ℓ, exact because D < log2 p), hence unconsumed
  → imbalance. Only the **leaf** index range-check (< 2^20, §3.2) is
  load-bearing for canonicalizing the tree's bottom;
- duplicate leaf production (a page listed twice) → two identical productions
  but only one consumable path to the single root → imbalance; omitting a
  merge or inventing extras → unconsumed tuples → imbalance.

## 2. Binding page images to the RAM ledger (closes the page-set hole)

v1's open soundness hole: nothing forces the multiproof's page set to cover
every page the segment touched — a prover could write page P, omit it from
the multiproof, and carry forged values across the boundary while both roots
verify. Fix: make the ledger itself force every accessed address into the
page set.

Per **listed** page, for **every** one of its 4096 bytes, the ledger
(MemoryChip) gets two injected entries (unconditionally — no gating flag) and
MemoryPageChip produces the matching tuples:

- a **ts=0 boundary write** `(addr, before_byte, 0, is_write=1,
  is_closing=0)` — value = the entering page image byte (also a leaf-hash
  input byte, same column);
- a **closing read** `(addr, after_byte, closing_ts, is_write=0,
  is_closing=1)` with `closing_ts = last_step_ts + 1 = final_state.timestamp`
  (shared `closing_ts_for`) — value = the exit page image byte (also a
  leaf-hash input byte, same column).

Read-consistency + `(addr, ts)` sortedness (the v6 machinery) then force:
- the closing read chains to the byte's last written value → `after_byte` =
  true exit value;
- for never-written bytes the closing read chains to the ts=0 write →
  `after_byte == before_byte` (unwritten bytes can't change);
- the first real read of a byte chains to the ts=0 write → execution reads
  `before_byte`.

New MemoryChip structural constraints (forward-only, next-row masks; the
guaranteed ≥1 padding row makes the cyclic wrap a padding transition, which
is **load-bearing**: it is what lets the group-start rule cover natural row 0
via the wraparound):
- **group start** — gate `g := is_real_next · (1 − is_same_addr)` (on
  padding→real wrap, `is_same_addr` is constraint-forced 0, so `g = 1` and
  row 0 is covered): `g · ts_next[i] = 0` for all 8 limbs, and
  `g · (1 − is_write_next) = 0`;
- **group end** — `is_real · (1 − is_same_addr) · (1 − IsClosing) = 0`
  (the last real row of every address group is a closing row). One direction
  suffices: a mid-group `is_closing=1` row would consume a second closing
  production that doesn't exist (the page chip emits exactly one per byte) →
  imbalance.

`IsClosing` is a new boolean MemoryChip column **added to the memory logup
tuple** (`REL_MEMORY_ACCESS_LOOKUP_SIZE` 14 → 15), the v6 precedent of adding
`is_write` to the register tuple. All other producers emit the constant 0
limb: CpuChip (constraint + interaction sides), Blake2bChip (256
emissions/compression), RistrettoEcall / RistrettoCombScalarBoundary /
RistrettoCombCompressOutput. Only MemoryPageChip emits `is_closing = 1` (on
closing-read tuples). A limb (not a chip-local column alone) is needed
because MemoryChip cannot otherwise recognize "closing row" — `closing_ts`
is per-proof data, and MemoryChip's claimed sum is not closed-form.

**ts-exclusivity prerequisites (review BREAKs — the v1 premise was false in
code, and both holes also undermine the v6 read-consistency claims on their
own):** the scheme requires that ts=0 and ts=closing_ts memory tuples are
producible ONLY by MemoryPageChip. Today:

1. **CpuChip step timestamps are not chained in-AIR.** `NextTimestamp` is
   filled as ts+1 but appears in no constraint; the program-execution relation
   is a multiset permutation that admits disjoint ts cycles, so a phantom
   step at ts=0 can emit an arbitrary store tuple. FIX (prerequisite, lands
   first): constrain `NextTimestamp = Timestamp + 1` limb-canonically on real
   rows (8-limb carry chain with boolean carries). With the v4/v5 boundary
   binding anchoring `initial_ts`/`final_ts`, every step ts is then provably
   in `[initial_ts, final_ts)`.
2. **Ristretto precompile mem-op timestamps are free witnesses.** The
   ristretto family's `Ts` columns are packed into memory tuples with no
   call-lookup binding to the ECALL step's timestamp (blake2b, by contrast,
   binds `CallTs` via `Blake2bCallLookupElements`). A from-scratch prover
   sets a ristretto output-write to ts=0 (entry forgery) or closing_ts (exit
   forgery, sorting just before the closing read). FIX (prerequisite, lands
   first): bind every ristretto mem-op ts to its ECALL step timestamp via the
   family's call/anchor relations (mirror the blake2b CallTs pattern).
3. **`initial_state.timestamp >= 1` is checked per-segment in
   `verify_standalone`** (NOT only in the chain wrapper — the production
   consumer verifies single proofs through `verify_standalone`; review
   BREAK). The chain check follows from per-segment checks + continuity.

**MemoryBoundaryChip is superseded and deleted**: its role (ts=0 values for
read-before-write addresses) is strictly contained in the per-page ts=0
injection. Its `collect_initial_bytes` enumeration moves into `page_merkle`
as the shared touched-set function. Deletion fallout (review-enumerated):
`chip_idx::MEMORY_BOUNDARY` + constant renumbering, both `BASE_COMPONENTS`
arrays, `chips/mod.rs` re-export, the per-address ts=0 injection block in
`memory.rs`, the positional `debug_claimed_sums` name table, dead
`side_note.num_initial_mem_entries`, and the explicit-components test
harnesses (`chip_isolated.rs`, `comb_value_sweep.rs`,
`ledger_readconsistency_gate.rs`, `memory*.rs`, `register_ledger_negative.rs`,
`bitmanip.rs`, `control_flow.rs`, `prove_vos_actor.rs`) which must carry the
new chip cluster wherever real memory traffic flows through a slice.

## 3. New chips

All four are **unconditionally active** (the page set is never empty, §0).

1. **Blake2bBoundaryChip** — the blake2b compression core (96
   rows/compression, same G-function/round schedule) **without** the
   memory-ledger and CPU-call bindings, fed from
   `side_note.merkle_blake2b_calls`. Produces one value tuple per compression
   on a new `Blake2bCompression` relation: `(h_in[64], m[128], t[8], f[1],
   h_out[64])` (265 limbs; stwo relations are const-generic with linear
   combine — the 130-limb ristretto-comb relation is working precedent),
   gated at row 95 where H/M/T/F replication and Output coexist.
   **Review-mandated additions over a naive core copy:**
   - **IsReal anchor (BREAK fix):** in the main chip, "IsReal is honest" is
     anchored by the CPU call-lookup balance, which this chip drops. Without
     a replacement, a prover lights up only row 95 and emits a fully forged
     tuple. So this chip adds: `is_real · (is_real − 1) = 0`, IsReal marked
     `#[mask_next_row]`, and a **preprocessed-gated** (not IsReal-multiplied)
     continuity `(1 − IsLastOfCompression) · (IsReal_next − IsReal) = 0`,
     making IsReal constant across each 96-row compression — so a row-95
     production implies the full V-chain from row 0.
   - **`is_real · T[i] = 0` for i ∈ 8..16 is a compression-CORE domain
     constraint** (it pins `V[13]`'s init) and is retained here even though
     it lives in the main chip's call-binding section (the tuple carries only
     t[0..8]).
   - Distinct `preprocessed_prefix` (e.g. `"blake2bnd"`) — same schedule
     content, distinct preprocessed-tree IDs.
   - The macro share covers the **arithmetic core only** (G-function, rounds,
     V-chain, output derivation, and the same for trace fill); all gating
     columns and ALL `RelationEntry` emissions stay chip-local, so neither
     chip can emit the other's relations.
   - `IS_PRODUCER = true` (the shared fill bumps `add_bitwise_and` /
     `add_range256` on `&mut SideNote`, exactly why Blake2bChip is a
     producer; a consumer-pass placement would under-count table
     multiplicities and reject honest proofs).
2. **MemoryPageChip** — one row per (listed page, 128-byte block), in
   page-major block order; preprocessed block-index schedule (block = row %
   32, gates derived from it are wrap-safe at exact-pow2 row counts — a
   single listed page is 32 rows with zero padding). Columns: `before[128]`,
   `after[128]`, `h_out_before[64]`, `h_out_after[64]`, page-index
   decomposition (nibble + 2 bytes, range-checked → index < 2^20; ledger
   addresses are then degree-1: `addr = idx·4096 + block·128 + cell`, with
   block/cell row-position constants). Per row: 128 ts=0 writes + 128 closing
   reads (memory relation, §2). Compression consumption per pass via **two
   gated emission families** (the h-chain): gated `is_block0 · is_real`,
   consume `(H_AFTER_LEAF_TAG, m_cur, t=256, f=0, h_out_cur)`; gated
   `(1 − is_last_block) · is_real`, consume `(h_out_cur, m_next, t_next,
   f_next, h_out_next)` with t/f from the preprocessed schedule (helper gate
   columns flatten the products to keep logup multiplicities degree-1). On
   each page's last block row, produce the leaf tuple `(20, idx,
   trunc32(h_out_before), trunc32(h_out_after))`. `IS_PRODUCER = true` (its
   range checks bump Range256 counts).
3. **MemoryMerkleChip** — the merge rows of §1; consumes two
   `Blake2bCompression` tuples per row (before/after node hashes, message =
   `l ‖ r ‖ 0^64` with constant pad limbs), the shared witness column set for
   witness slots, level range [0,19] as in §1.
4. **MemoryRootBoundaryChip** — mirror of `register_memory_boundary.rs`: a
   single real row consuming `(0, 0, initial_root, final_root)` on the
   MerkleNode relation; its claimed sum is closed-form in the public roots →
   bound via `boundary_binding::expected_memory_root_sum` +
   `BoundaryChipPositions.memory_root_boundary`, checked **unconditionally**.

## 4. Plumbing

- `SegmentState` gains `initial_root: [u8;32]`, `final_root: [u8;32]`
  (keep `memory_commitment` as-is); derived `PartialEq` automatically extends
  both chain-continuity struct-eqs.
- FS mix: the roots enter the channel immediately after the `final_ts` mix,
  identically at the three sites (`prove.rs`, `verify.rs`,
  `verifier/src/lib.rs`) — before lookup-element draw, so the claimed-sum
  recomputation is sound. The standalone-verifier mix and the root binding
  equality are **strictly unconditional** (no gating on any prover-derived
  signal); the host `verify.rs` path keeps parity with its existing
  `closing_chip_active` gate, which is not a trust boundary.
- `boundary_positions_in_mask` **requires** the new chips' mask bits
  (returns None → reject if `MEMORY_ROOT_BOUNDARY`, `MEMORY_PAGE`,
  `MEMORY_MERKLE`, or `BLAKE2B_BOUNDARY` is missing) — the mask-level guard
  the v1 text wrongly assumed already existed. `check_boundary_claimed_sums`
  gains the fourth equality (`expected_memory_root_sum` vs the root chip's
  claimed sum).
- `chip_idx` / both `BASE_COMPONENTS` arrays: remove `MEMORY_BOUNDARY`, add
  `BLAKE2B_BOUNDARY`, `MEMORY_PAGE`, `MEMORY_MERKLE`, `MEMORY_ROOT_BOUNDARY`
  (net +3, `COUNT` 28 → 31), all unconditionally active.
- Side note: `ingest_memory_pages(&mut SideNote)` builds the **idempotent**
  per-segment payload (listed page set via the shared enumeration, entering/
  exit page images, frontier, the merge schedule, and
  `merkle_blake2b_calls` — **one call per consumption, duplicates included**:
  identical compressions are common, e.g. two all-zero pages, or a read-only
  page whose before/after passes coincide; any dedup under-produces and
  rejects honest proofs). Called on the **prove path only** (prove_impl +
  segment driver), rebuild-from-scratch each time. The verify paths never
  need the payload: the FS mix reads proof fields, preprocessed regeneration
  is row-index-pure, and the component set is constant (all new chips
  always-on).
- `prove.rs` assembles `initial_root`/`final_root` from the same side-note
  data the chips trace (by-construction equality, like `initial_regs`).
- Format bump **v6 → v7** + history entry (component-set change, tuple-width
  change, new mixes, new SegmentState fields).
- **Chain/segment anchoring (review BREAK fix — v1 left the anchor
  out-of-band, making the chain's memory claim only relative):**
  - `verify_standalone` rejects `initial_state.timestamp < 1` (§2);
  - `verify_chain_standalone(proofs, preprocessed_commitment,
    expected_initial_root)` — the expected starting-image root is a
    **required parameter** checked against `proofs[0].initial_state
    .initial_root` (the memory analogue of the program commitment), and the
    function returns the chain's `final_root` so consumers pin the
    post-state. Callers compute the expected root host-side via
    `page_merkle` (the prover extension knows the program + input image).
- Cost (review-corrected): Blake2bBoundary ≈ **1504 cells/row** (2544 minus
  the 1040 pointer/address cells) × 2 passes × (23×32 leaf + ~460 node) =
  **2392 compressions max** → ~230K rows (2^18) — the dominant new cost,
  plausibly ~5–8 GB peak in the prover pipeline. Before the capstone, run
  the single worst segment (max touched pages) with peak-RSS instrumentation;
  fall-backs if over budget: smaller segments, or trimming the boundary
  chip's row-95-only witness columns. MemoryPageChip ≈ 736 rows (~530
  cells/row). Ledger growth: 2×4096×23 ≈ 188K rows (may bump MemoryChip's
  log_size by 1 near pow2 boundaries).

## 5. What the verifier ends up guaranteeing

For a chain accepted by `verify_chain_standalone(proofs, commitment,
expected_initial_root)`:
- every segment executed the committed program (preprocessed commitment),
  with register/pc/ts continuity (v4–v6) and `initial_ts ≥ 1`;
- within each segment, every RAM read/write is ledger-consistent (v6), every
  accessed address lies in the listed page set (§2 group constraints), the
  entering bytes of listed pages hash to `initial_root` and the exit bytes to
  `final_root` (§1–§3), and untouched subtrees are carried unchanged (§1
  witness reuse);
- across segments, `final_root_i == initial_root_{i+1}` (struct-eq over
  bound fields), and `initial_root_0 == expected_initial_root`;
- hence the returned final root commits the true RAM image produced by
  running the committed program from the supplied starting image. The
  remaining trust scope: the caller must know `expected_initial_root`
  (program + input image), exactly as it must know the program commitment.

## 6. Implementation order (each step keeps the tree green)

0. **Prerequisite AIR fixes** (independently valuable; harden v6 claims):
   CpuChip `NextTimestamp = Timestamp + 1` carry-chain constraint; ristretto
   mem-op ts binding to the ECALL step. Negative tests for both.
1. `page_merkle` host module + spec tests (root vs naive full tree;
   multiproof vs reference; default-page chains; host↔library blake2b-256
   equivalence on tagged messages).
2. Blake2b core-sharing refactor (macro-extract arithmetic core + fill; **no
   behavior change**, all blake2b tests green) — isolated commit.
3. Blake2bBoundaryChip + `Blake2bCompression` relation + side-note plumbing +
   chip-isolated tests (known compression; tamper bytes → reject; tamper the
   IsReal pattern (1 only at row 95) → reject).
4. Ledger restructure: `is_closing` limb (14→15) across the producer chips +
   MemoryChip group-start/group-end constraints + per-page injection +
   MemoryBoundaryChip deletion + harness migration (§2 fallout list).
5. MemoryPageChip + MemoryMerkleChip + MemoryRootBoundaryChip.
6. SegmentState/FS/boundary_binding/format v7 + verifier API changes (§4).
7. Gate tests + full regressions + worst-segment RSS measurement + capstone
   re-prove + rebuild prover cdylib.

## 7. Gate tests (negative; mirror `ledger_readconsistency_gate`)

- forged `before_byte` on a ts=0 row (entry forgery) → REJECTED;
- forged `after_byte` / closing-read value (exit forgery) → REJECTED;
- omitted touched page (write to P, list set without P) → REJECTED
  (group-start/closing imbalance);
- witness-sibling mismatch between passes (untouched-subtree forgery) →
  structurally impossible (single column set) — assert via construction
  review + a tamper test on the merge row's witness columns;
- Blake2bBoundary IsReal=1 only at row 95 (forged compression) → REJECTED;
- single proof with `initial_ts = 0` → REJECTED by `verify_standalone`;
- chain with wrong `expected_initial_root` → REJECTED;
- mask missing any of the four new chips → REJECTED;
- boundary-override harness (`prove_with_boundary_override`) extended to
  ship forged roots over honest columns → REJECTED.

## Appendix A — Prerequisite step 0.2: ristretto mem-op ts binding

**Status: NOT YET BUILT — needs its own deep-read + adversarial pass before
implementation (the multiplicity accounting below is the open problem).**

### The gap (verified in code)

The three ristretto-family memory producers emit `MemoryAccessLookupElements`
tuples `(addr[4], value[1], ts[8], is_write[1])` whose **`ts` limbs are free
witness columns** with no binding to a genuine ECALL step timestamp (contrast
blake2b, which binds `CallTs` via `Blake2bCallLookupElements` carrying the
step ts):
- `RistrettoEcallChip` (`ristretto_ecall.rs:82-113`): only IsReal/IsWrite
  booleans constrained; `ts` packed straight into the tuple.
- `RistrettoCombScalarBoundaryChip` (`ristretto_comb_scalar_boundary.rs`):
  free `Ts`.
- `RistrettoCombCompressOutputChip` (`ristretto_comb_compress_output.rs`):
  free `Ts`.

A from-scratch prover sets a ristretto output-write tuple's `ts` to **0**
(collides with the §2 per-page ts=0 boundary write → entry forgery) or to
**closing_ts** (sorts just before the §2 closing read → exit forgery). With
CpuChip step timestamps now chained (commit `515c5b4`), the fix only has to
prove every ristretto mem-op ts is a genuine ristretto-ECALL step timestamp:
that lands it in `[initial_ts, final_ts)`, excluding both 0 (`< initial_ts`,
since `initial_ts ≥ 1`) and `closing_ts` (`= final_ts`, never a step ts).

**Money-path relevance (verified):** all three chips are ACTIVE on the
voucher/clerk conservation proof — cipher-clerk's Schnorr signatures and
Pedersen commitments use fixed-basepoint mult (`crypto/sig.rs:54-63,91-122`,
`crypto/commit.rs:36-50`), which routes through the comb family
(`side_note.rs:530-538`, gated active at `lib.rs:411-415`), plus variable-base
+ scalar_reduce_wide + scalar_binop through `RistrettoEcallChip`. So the fix
must cover all three chips.

### The mechanism (call relation, mirror of blake2b)

A new `RistrettoCallLookupElements` relation carrying the ECALL step ts (and
ideally the output_ptr, to also pin the address). CpuChip detects ristretto
ECALL steps (imm ∈ the 5 ECALL ids — needs a new `IsRistrettoEcall` column +
pointer snapshot columns, parallel to `IsBlakeEcall`/`Phi*`) and PRODUCES one
tuple per ristretto ECALL step. The handling chip(s) CONSUME one per call.

### The open problem (why it needs its own pass)

The consumer multiplicity is split across chips by ECALL kind, and the split
is **not derivable from the opcode**:
- variable-base scalar_mult / point_add / scalar_reduce_wide / scalar_binop:
  `RistrettoEcallChip` handles all 96 mem-ops (consumer count k = 1);
- **fixed-base** scalar_mult: `RistrettoEcallChip` handles the 32 point reads,
  `RistrettoCombScalarBoundaryChip` the 32 scalar reads,
  `RistrettoCombCompressOutputChip` the 32 output writes (k = 3).

`ECALL_RISTRETTO_SCALAR_MULT` covers both fixed and variable; fixed-vs-variable
is decided at runtime by whether the point argument equals the basepoint
(`tracing.rs:132-142`), which CpuChip cannot see. So CpuChip cannot emit a
per-step multiplicity of "k chips will consume this call." Candidate
resolutions to evaluate in the dedicated pass:
1. **Universal anchor:** `RistrettoEcallChip` handles ≥ the input/point reads
   of EVERY ristretto call, so CpuChip produces +1 per ristretto ECALL step
   and `RistrettoEcallChip` consumes −1 per call (clean 1:1). The comb chips'
   ts is then bound **separately** by threading a ts limb through the existing
   comb cross-chip relations (`RistrettoCombScalarBoundary`,
   `RistrettoCombCompressOutput`) so their ts is forced equal to a value the
   anchor/comb chain already vouches for — needs verifying those relations'
   producers are themselves ts-bound (avoid circularity: both ends read
   side_note today).
2. **Per-role relations** keyed by output_ptr / a role discriminator so each
   chip consumes a distinct tuple and CpuChip produces all of them — but
   CpuChip still can't tell which roles exist for a SCALAR_MULT step.
3. **Intra-call ts-equality prerequisite:** whichever option, confirm each
   chip forces all rows of one call block to share a single `Ts` (mask-next-row
   within the block) — else binding one row per call leaves the other 95 free.

### Deliverables for the dedicated pass

Deep-read the exact row/call-block layout + call-boundary preprocessed signals
of all three chips and the comb cross-chip relations; pick a resolution;
adversarially review it (free-ts entry/exit forgery REJECTED; honest money
path still balances); validate with the ristretto chip-isolated tests + a
`voucher_check_smoke` prove/verify (207s). Format bump folds into v7.
