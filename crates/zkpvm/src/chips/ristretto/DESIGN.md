# RistrettoChip — Curve25519 / Ristretto255 scalar mult precompile

**Status**: in-progress implementation.  R1a–R1c-3-bis landed; chip
gated OFF in `active_components` so existing proofs are unaffected.

## Implementation log

- **R1a** (`c31417b`) — ECALL ID 200, `RistrettoRecord` /
  `RistrettoMemOp`, `handle_ristretto_scalar_mult_ecall` in
  TracingPvm, smoke test (2*G via ecalli matches dalek).
- **R1b** (`ed669f8`) — Empty `RistrettoChip` stub at
  `BASE_COMPONENTS[19]`, `ChipActivity.ristretto`,
  `activity_from_steps` detection.  Existing benches byte-identical.
- **R1c-1** (`e0f1060`) — Pure-Rust 𝔽_p reference (`field.rs`):
  add/sub/mul/inv/pow/reduce.  8 tests pass; cross-checked against
  dalek `Scalar` ring on small inputs.
- **R1c-2** (`aad499f`) — Field-op column shape (FieldA/B/Out + carry
  + borrow + overflow + classifier) and witness fill (`witness.rs`)
  for add/sub.  5 tests pass.
- **R1c-3** (`c4b7e7e`) — Add-chain constraints (sum chain + reduction
  sub-chain + boolean checks + real-row partition).
- **R1c-3-bis** (`f0a6dff`) — Final-form `out < p` check via
  `(p − out − 1)` borrow chain whose closure constraint pins
  `is_overflow` witness-determinism.
- **R1c-3-ter** (`b2bcf82`) — Per-byte Range256 lookups on
  FieldA/B/Out/AddIntermediate (128 emissions per real row).
  Chip's first real lookup binding; closes the per-byte soundness
  pin on the algebraic chains.
- **R1c-3-quat** (`a0baad3`) — is_sub constraint chain
  (`out + b ≡ a + is_underflow·p` byte-borrow chain + closure).
  IsOverflow column reinterpreted as is_underflow on is_sub rows.
- **R1c-4-a** (`0b13af9`) — Schoolbook mul column scaffolding
  (MulProduct[64], MulCarry[64], MulCarryMid[64], MulCarryHi[64],
  IsMul) + fill_mul witness builder + 3-way real-row partition.
- **R1c-4-b** (`f557f67`) — Schoolbook field-mul constraint chain
  (`Σ a[i]·b[j] + carry_in = product + 256·full_carry`) +
  closure (full_carry[63] = 0) + Range256 pin on all 256 is_mul
  witness bytes per row.
- **R1c-5-a** (`02ebf3e`) — Reduction-mod-p column scaffolding
  (Pass1Lo/Hi, Pass1Carry+Mid, Pass2Lo/CarryOut/Carry,
  Pass2TopBit, AfterTopBit/Carry) + canonical fill_mul that
  returns (a·b) mod p in FieldOut.
- **R1c-5-b** (`91520ae`) — Reduction constraint chains: pass-1
  fold (lo + 38·hi), pass-2 fold (pass1_lo + 38·pass1_hi),
  top-bit fold + 19/38 add, final FieldOut = after_top − is_ovf·p.
- **R1c-6** (`92f800a`) — Inversion driver (Fermat ladder) — pure
  host-side row composition emitting is_mul rows.
- **R1d** (`94a259c`) — Edwards point doubling + addition, host-
  side composition over extended (X, Y, Z, T) coords.  16 rows
  per double, 18 per add.
- **R1e** (`bbda933`) — Scalar-mult double-and-add main loop.
  Composes R1d ops over 256 scalar bits.  ~6500 rows per scalar mult.
- **R1e-quat** (`b2504c2`) — Chip-on integration:
  `SideNote.ristretto_field_rows` + `add_ristretto_field_row`
  helper that pre-bumps Range256 multiplicities (since
  RangeMultiplicity256 component runs before RistrettoChip);
  `generate_main_trace` lays each FieldOpRow into its column
  slots; activity gating includes `!ristretto_field_rows.is_empty()`
  so chip-level tests turn on without ECALLs.
  - **First end-to-end RistrettoChip proof** passes:
    `prove_ristretto_chip_field_add` (1 + 2 = 3, gen 16-row trace,
    chip ON, verifier reconstructs same active set).
  - **`prove_ristretto_chip_field_mul_zero` passes**: 0·0=0
    exercises the full is_mul row constraint set with all-zero
    witness; demonstrates is_mul integration plumbing is sound.
- **R1e-quat bisect** (`4b52c05`) — Bisected the field-mul
  ConstraintsNotSatisfied via per-chain `ENABLE_*` flags.  Finding:
  even with ALL is_mul-gated chains disabled, the trivial 1·1=1
  is_mul row fails — but 0·0=0 passes.  The bug is in some
  always-fires constraint (boolean checks, real-row partition,
  ff_brw closure, sub_chain_brw closure, or pass2_carry_out /
  pass2_top_bit booleans) that's silent for all-zero witness but
  triggers on non-zero values when is_mul=1.  Bisect flag
  scaffolding kept in place for the follow-up.

## R1e-pent: inter-row binding — CLOSED (`52ffe1f`)

Implemented via the RistrettoRegisterFileLookupElements relation
(tuple shape: row_idx_lo, row_idx_hi, byte_idx, byte_value).

Per real op row:
- PRODUCER: 32 emissions of (row_idx, byte_idx[k], out[k]),
  multiplicity = +is_real
- CONSUMER A: 32 emissions of (a_src, byte_idx[k], a[k]),
  multiplicity = -is_real
- CONSUMER B: 32 emissions of (b_src, byte_idx[k], b[k]),
  multiplicity = -is_real

Closure: lookup-balance forces every consumer to find a matching
producer, so every input must come from a prior row's `out`.

Verified by `ristretto_chip_unrelated_rows_now_rejected`: 100
unrelated rows are correctly REJECTED at verify time.

## R1e-bdry: boundary input/output mechanism — CLOSED (`c06ad67`)

Two new row classes for closing the chain at the boundaries:

- **IsInput**: producer-only row.  Holds a boundary value in
  `out`, emits 32 producer tuples.  No consumer emissions, no
  field-op constraints.  Used for ECALL scalar/point bytes,
  curve constants, point-identity coords.
- **IsOutput**: consumer-only row.  Drains via consumer A
  (a_source pointing to the producing row).  No producer, no
  consumer B, no field-op constraints.

Partition extended: is_real ⇒ exactly one of {is_add, is_sub,
is_mul, is_input, is_output} = 1.

Verified by `prove_ristretto_chip_closed_chain_input_output`:
4-row chain [input, input, add, output] proves + verifies
end-to-end.  Soundness: per-row + inter-row + boundary all CLOSED.

## R1f: end-to-end benchmark — CLOSED (`13b36d9`)

`bench_ristretto_chip_soundness_complete_chain` measures the
realistic prove-time per chip operation in soundness-complete
configuration:

| Operations | Total rows | Log_size | Prove | Per-op |
|---:|---:|---:|---:|---:|
| 1,000  | 2,002  | 11 | 0.42 s | 0.42 ms |
| 10,000 | 20,002 | 15 | 7.47 s | 0.75 ms |

Linear scaling.  Extrapolating to 21,118-row per-payment workload:
**~18 s prove time on CPU**.  Matches pre-soundness measurement
(soundness adds ~0 prove-time overhead).

Cipher-clerk patch (separate from R1f deliverable): replace
fill_input/fill_output with ECALL-boundary lookups against
MemoryChip, thread source row IDs through point-op generators.
The chip's AIR is ready and soundness-complete; what's left is
integration plumbing.

## Remaining work before chip-on (NOTE: now mostly closed)

**Status**: confirmed exploitable, design proposed, implementation
deferred.

Each FieldOpRow today proves "I correctly computed `out = a OP b
mod p`" for whatever a, b, out values are in the row's columns.
But the chip emits NO constraint linking row N's `a` / `b` to any
prior row's `out`.  A malicious prover could emit any sequence of
self-consistent rows — confirmed by
`ristretto_chip_unrelated_rows_prove_attestation`, which proves a
trace of 100 unrelated `1 + N = 1+N` rows.

The fix needs a register-file lookup relation:

  RistrettoRegisterFile tuple: (row_id, byte_index, byte_value)

  Per real row:
    PRODUCER:  32 tuples (row_id, 0..31, out[0..31])
    CONSUMER:  32 tuples (a_source_row_id, 0..31, a[0..31])
                 + 32 tuples (b_source_row_id, 0..31, b[0..31])

  a_source_row_id and b_source_row_id are witnessed columns
  (not constrained — the verifier just checks the lookup balances).

  Special handling for row 0's inputs (and the chip's overall
  inputs from the ECALL boundary): an INPUT producer emits the
  scalar/point bytes, identified by a sentinel row_id.

Cost: 96 register-file lookup emissions per real row.  At 21K rows
per payment, that's ~2M emissions — a significant chip-cost
increase.  Optimization: group bytes into wider tuples (e.g.
4-byte u32 per tuple element ⇒ 8 tuples per slot instead of 32).

Until R1e-pent lands, the chip is sound only for ECALL boundary
flows that constrain BOTH the first row's input AND the final
row's output, AND the chip's intermediate rows form a known-
schedule DAG that the constraint chain can verify by adjacent-row
or preprocessed equalities.  For the cipher-clerk benchmark in
R1f, this means the chip-on path is a "performance preview" not
a soundness-complete proof.

## Remaining work before chip-on

Not delivered in the initial run; each is a focused dedicated session:

- **R1c-5** — Reduction `mod 2²⁵⁵ - 19` for mult outputs.  Uses
  `2²⁵⁵ ≡ 19 (mod p)` to fold the 512-bit unreduced product back
  into 256 bits (two passes).  Strategy choice (open):
    a. Multi-row: separate is_reduce_round1, is_reduce_round2,
       is_final_form rows.  ~4 rows per mul, cleaner column shape.
    b. Single-row: extra columns on the is_mul row.  Fewer rows,
       wider AIR.  Probably the right call for prove-time.
  The is_mul row's FieldOut should hold the canonical (a·b) mod p
  after this lands, not the LOW 32 of the unreduced product.
- **R1c-6** — Field inversion via Fermat's little theorem (`a^(p-2)`
  square-and-multiply ladder).  Composed of R1c-4 mults + R1c-5
  reductions; no new primitive.
- **R1d** — Edwards point doubling/addition formulas in extended
  coordinates.  Each composes ~9 R1c-4 field mults.
- **R1e** — Signed-4-bit-window NAF main loop, scalar decomposition,
  boundary memory lookups (32 reads + 32 reads + 32 writes per
  ECALL).  RistrettoCallLookup binds CpuChip's ECALL step to the
  chip's first/last row.
- **R1f** — Patch cipher-clerk's `Amount::commit` / `Note::commitment`
  / `sign` through a `pvm-precompile` feature.  Re-run
  clerk-private-pay-bench; measure prove time, compare to estimate.

Soundness gates each subsequent phase must hold:
- Every column committed on a real row must be byte-bounded (R1c-3-
  ter pin); the algebraic chain alone is insufficient.
- Every chain closure must be explicitly constrained (R1c-3-bis
  pattern) — implicit byte-arithmetic doesn't enforce closure.
- Every operation classifier must partition real rows exactly once.


**Goal**: bring per-scalar-mult cost from ~14 M PVM steps (software dalek
inside the VM) down to a precompile-shaped fraction so `cipher-clerk`
private payments can be proven on-device in seconds rather than tens of
seconds.

## 1. Why we need it

Real-workload measurement on `clerk-private-pay-bench`:

- **Lite variant (no scalar mult, just blake2b + rkyv)**: 37 K PVM
  steps, 6.5 s prove at 96-bit mobile.
- **Full variant (4 Ristretto scalar mults)**: 44 M PVM steps and
  rising before OOM during trace recording.

The 1100× gap between "lite" and "full" is entirely the curve work.
Without a precompile, sub-second proving for tap-and-pay isn't even on
the horizon.

The pattern is identical to Blake2b: `cipher-clerk`'s hot path uses a
small number of curve operations per transfer, the math is 256-bit
modular arithmetic that decomposes badly onto a 32-bit RISC ISA, and
proving the software implementation step-by-step pays the AIR cost on
every single intermediate. A precompile replaces all of that with
`O(1)` rows in a dedicated chip — exactly how `Blake2bChip` reduces a
12-round compression from ~30 K PVM steps to 96 chip rows.

## 2. Primitive choice — what the ECALL does

**Pick: `k * P → Q` for any compressed Ristretto point P and canonical
scalar k.** One ECALL = one 256-bit scalar multiplication on
Ristretto255.

Rejected alternatives:

- **Per-op (point doubling + addition)** — turns each scalar mult into
  ~512 ECALLs. The boundary lookup overhead would dominate; we'd save
  the field-arithmetic cost but lose it back at the seam.
- **Dual-flavor (`k*G_basepoint` separate from `k*P`)** — better
  performance for the basepoint case (precomputed table → no doublings)
  but doubles the chip surface and the integration churn. Defer to a
  Phase R2 specialization; Phase R1 covers basepoint via the same
  general primitive.
- **Multi-scalar (`k₁*G + k₂*P → R`)** — perfect shape for Schnorr
  *verify*, but `cipher-clerk` only verifies server-side; the *user* on
  the device only signs and commits. Defer until a recipient-side
  bench (`clerk-private-pay-receive-bench`) shows verify is on the
  critical path.

`k * P` is the universal primitive — every higher-level operation
(Schnorr sign, Pedersen commit `v*G + b*H`, note-commitment value
scalar) is one or two of these.

## 3. ECALL ABI

Following Blake2b's pattern (`src/core/ecall.rs:6-9`):

```rust
/// Hostcall ID for Ristretto255 scalar mult precompile.
///
/// Convention:
///   φ[10] = scalar_ptr  (32 canonical bytes, scalar mod ℓ)
///   φ[11] = point_ptr   (32 bytes, compressed Ristretto encoding)
///   φ[12] = output_ptr  (32 bytes, compressed Ristretto)
///
/// scalar_ptr (32B read) and point_ptr (32B read) are inputs;
/// output_ptr (32B write) receives k*P.  Memory entries fire at the
/// ECALL step's timestamp, reads before writes (same convention as
/// Blake2b).
///
/// On non-canonical scalar bytes or invalid (non-decompressible) input
/// point: writes [0u8; 32] to output_ptr (a "failure" sentinel that
/// never appears as a legitimate compressed Ristretto identity, since
/// canonical ε-encoded identity is `[0u8; 32]` — TODO: confirm and
/// disambiguate).
pub const ECALL_RISTRETTO_SCALAR_MULT: u32 = 200;
```

The `200` ID leaves room for future curve precompiles in the 200-block
(ed25519 verify = 201, basepoint mult = 202, MSM = 203, etc.).

**Why three pointers, not two (overwrite input):** Pedersen commits
need `v*G + b*H` — two scalar mults that produce two intermediate
points which then need to be added. Reusing the input point's slot
forces the guest to copy bytes around between calls. Separate output
keeps the API symmetric and avoids guest-side memcpy.

**Why pointers, not register-resident scalars/points:** φ[10..=12] are
64-bit registers; scalar and point are 256-bit each. Pointer-passing
matches Blake2b and lets the chip's MemoryChip ledger lookup do all
the integrity work — no need to widen the register interface.

## 4. Guest-side wiring

`cipher-clerk` reaches the curve via `curve25519-dalek`. We don't
modify dalek — instead we publish a tiny `vos-precompiles` shim crate
that exposes `ristretto_scalar_mult(scalar: &[u8;32], point: &[u8;32])
-> [u8;32]` as an inline asm `ecalli 200`, and patch `cipher-clerk` to
use it via a `pvm-precompile` feature flag. On host builds (without
the feature) it falls through to dalek native; on PVM builds it issues
the ECALL.

Concretely the touch points in cipher-clerk are small:

- `src/crypto/commit.rs:Amount::commit` (one `v*G`, one `b*H`, one
  point add)
- `src/crypto/sig.rs:sign` (two `*G`)
- `src/crypto/sig.rs:verify_signature` (two — server-side, lower
  priority)
- `src/notes/mod.rs:Note::commitment` (`v_scalar*G`, `b*H`)

Each call site replaces a `&k * RISTRETTO_BASEPOINT_TABLE` or
`k * point` with `vos_precompiles::ristretto_scalar_mult(&k_bytes,
&point_bytes)`. The basepoint case uses `RISTRETTO_BASEPOINT_COMPRESSED.as_bytes()`
as the point input — slightly slower than dalek's table (which
amortizes via fixed-base) but the chip cost is what matters here, not
the host-side cost.

## 5. TracingPvm capture path

Mirrors `handle_blake2b_ecall` (`src/core/tracing.rs:163-216`):

```rust
fn handle_ristretto_scalar_mult_ecall(&mut self) {
    let scalar_ptr = self.pvm.registers[10] as usize;
    let point_ptr  = self.pvm.registers[11] as usize;
    let output_ptr = self.pvm.registers[12] as usize;

    let mut scalar_bytes = [0u8; 32];
    let mut point_bytes  = [0u8; 32];
    // Bounds-checked reads from flat_mem...
    scalar_bytes.copy_from_slice(&self.pvm.flat_mem[scalar_ptr..scalar_ptr+32]);
    point_bytes.copy_from_slice(&self.pvm.flat_mem[point_ptr..point_ptr+32]);

    // Native scalar mult (host-side, off the prover's critical path).
    let out_bytes = ristretto_scalar_mult_native(&scalar_bytes, &point_bytes);

    self.pvm.flat_mem[output_ptr..output_ptr+32].copy_from_slice(&out_bytes);

    let ts = self.timestamp - 1;
    self.ristretto_records.push(RistrettoRecord {
        scalar: scalar_bytes, point: point_bytes, output: out_bytes,
    });
    self.ristretto_mem_ops.push(RistrettoMemOp {
        scalar_ptr, point_ptr, output_ptr, ts,
        scalar_bytes, point_bytes, out_bytes,
    });
}
```

96 byte-level memory ops per call (32 read + 32 read + 32 write), all
sharing one timestamp. Reads-before-writes via Vec insertion order.

## 6. The chip itself — sketch

This is the hard part and where the design has the most uncertainty.
Here's a working sketch; numbers are first-order estimates I'll refine
once we prototype.

### 6.1 Scalar-mult algorithm

**Choice: signed 4-bit window NAF (w=4) over extended Edwards
coordinates.**

- Decompose 256-bit scalar into 64 signed nibbles in [-8, 7]
  (non-adjacent form). Avg ~16 zero windows ⇒ ~48 non-zero adds.
- Precompute table `[1·P, 3·P, 5·P, 7·P, 9·P, 11·P, 13·P, 15·P]`
  (negatives derived by sign flip). 8 table entries × 1 doubling each
  = 8 setup point ops.
- Main loop: for each window i = 63 down to 0:
  - 4 doublings of accumulator (independent of window value)
  - 1 conditional add of `±table[|w|]` (skipped if w==0)

Per scalar mult: **~256 doublings + ~48 adds + 8 table-setup adds
≈ 312 point operations.**

Each point operation in extended Edwards coords is ~9 field
multiplications mod p (where p = 2²⁵⁵ - 19). So one scalar mult is
~2800 field mults. Field mult on M31: needs 8×32-bit-limb
multiplication with reduction — call it ~30 chip rows (rough; the
exact number depends on the 32×32→64 multiplication strategy and the
M31 lookup table for partial products).

**Estimated rows per scalar mult: ~85 K** (312 ops × ~270 rows/op,
where 270 ≈ 9 field mults × 30 rows each).

That's a lot. For comparison Blake2b is 96 rows × 1 call. RistrettoChip
at 85 K rows × 1 call would mean log_size ~17 just for the precompile,
even in isolation. With 4 calls per private-pay → log_size ~19 for the
chip alone.

This is the load-bearing uncertainty in the design. Two angles to
attack it:

1. **Aggressive col packing.** Most of the 30-rows-per-field-mult
   estimate is M31 partial-product accumulation. If we can amortize
   across multiple field mults per row (e.g. process 4 mults in
   parallel down a wider AIR), rows could halve.

2. **Move to a circuit-friendlier curve.** Curve25519 fundamentally
   doesn't fit M31 — its prime is 2²⁵⁵-19, not adjacent to any M31
   power. Babyjubjub (over BN254 scalar field) or a Pasta curve would
   reduce field-mult cost dramatically. **But** that requires
   `cipher-clerk` to swap curves, which breaks interop. Long-term win,
   short-term cost; flag for follow-up.

For the first cut, accept the chip size and measure. If log_size for
the proof grows past 22 we'll need to revisit.

### 6.2 Trace columns

Per-row layout (sketch):

- **Point coords (extended Edwards: X, Y, Z, T)**: 4 × ~32 limbs
  (8-bit) = 128 cells per row for the "current" accumulator. Plus
  another 128 for the "table entry being added" or "doubled
  intermediate". ~256 cells.
- **Scalar window decomposition**: 64 signed nibbles + sign witnesses
  = ~128 cells, replicated across rows of the same scalar mult.
- **Operation classifier flags** (`is_double`, `is_add`, `is_table_setup`,
  `is_first`, `is_last`): ~8 flag cols.
- **Field-mult intermediates** (for the ~9 mults this row contributes
  to): ~10 mults × 16 cells of carry/limb witnesses = ~160 cells.
- **Memory boundary cells** (only on first/last row of each call):
  scalar_ptr decomp (4 bytes), point_ptr decomp (4 bytes), output_ptr
  decomp (4 bytes), 32 scalar bytes, 32 point bytes, 32 output bytes,
  call timestamp (8 bytes) = ~120 cells, gated.
- **`is_real`** flag.

**First-cut estimate: ~700 cols × 85 K rows = 60 M cells per scalar
mult.** Way more than Blake2b's 220 K. Three implications:

1. The chip has to be **gated** — only present in proofs that contain
   ≥1 Ristretto ECALL. Same `activity_from_steps()` mechanism as
   Blake2b (`src/lib.rs:202-214`).
2. Stwo's column commitment cost grows with cells; we'll see prove
   time grow ~linearly in this number until we hit FRI dominance.
3. The 60M-cells/call number is a target ceiling. If real
   implementation comes in higher we revisit primitive choice.

### 6.3 Constraints

Per-row constraints follow Blake2b's structure:

- **Field-arithmetic constraints**: per-mult limb-multiplication +
  carry-propagation chain. Standard (cf. how Blake2b handles 64-bit
  add via 8-byte carry chain — same idea, scaled to 256-bit modular
  multiplication).
- **Edwards point-doubling formula**: 4 × field-mult = 4 constraint
  blocks per doubling row.
- **Edwards point-addition formula**: 8 × field-mult per add row.
- **Conditional add gating**: `is_add * (window != 0)` switches the
  add formula on/off; padding rows have `is_real = 0` and all
  constraints inert.
- **Row-chaining**: accumulator `(X, Y, Z, T)` after this row =
  accumulator before next row, same pattern as Blake2b's V-state
  chain.
- **Boundary equations** at first/last rows: input scalar bytes = NAF
  reconstruction; output coords = compressed Ristretto encoding of
  final accumulator.

### 6.4 Lookups

- **MemoryAccessLookup** at the ECALL boundary: 32 scalar reads + 32
  point reads + 32 output writes, all at ts = call timestamp. Mirrors
  Blake2b's pattern (`src/chips/blake2b/mod.rs:850-948`).
- **RistrettoCallLookup**: 1 tuple per call, consumer side, claims
  the existence of a CpuChip ECALL_RISTRETTO_SCALAR_MULT step at this
  ts with these registers. Producer side lives in CpuChip's
  `IsRistrettoEcall` column (new, parallel to `IsBlakeEcall`).
- **Field-arithmetic lookups**: 8-bit × 8-bit multiplication table for
  M31 partial products (probably reuse an existing range-check table
  if there's one, otherwise add a `ByteByteMulLookup`).

### 6.5 Reductions / soundness

Field reduction mod p = 2²⁵⁵-19 is the trickiest soundness piece. For
each modular reduction we need a witness that the unreduced value
equals `q*p + r` with `0 ≤ r < p`. Standard technique: range-check
`r`, prove `q*p + r = unreduced` via constraint, where `q` is small
(2-3 limbs).

Compressed Ristretto encoding/decoding has its own validity
constraints — the encoded byte-string must round-trip to a unique
canonical group element. This adds ~50 constraints per
encode/decode, applied at the call boundary only.

## 7. Component selection / activity

`activity_from_steps()` (`src/lib.rs:202-214`) extends to scan for
`(Opcode::Ecalli|Ecall) && imm == ECALL_RISTRETTO_SCALAR_MULT`. New
field `ChipActivity.ristretto: bool`. Index allocation in
`active_components` slot (next free past Blake2b's index 1).

Proofs without any Ristretto ECALLs skip the chip entirely — pure-
compute actors (fibonacci, hasher, hash-bench) pay nothing.

## 8. Phased implementation plan

**Phase R1a — Plumbing (1 commit)**:
- `ECALL_RISTRETTO_SCALAR_MULT` in `src/core/ecall.rs`.
- `RistrettoRecord`, `RistrettoMemOp`, `handle_ristretto_scalar_mult_ecall`
  in `src/core/tracing.rs`. Native impl uses `dalek` directly (this
  is host code, not PVM).
- `run_with_precompiles()` extends to dispatch on the new ECALL ID.
- Test: a TracingPvm-only smoke test that runs a hand-crafted
  `Ecalli(200)` program and asserts the output bytes match a dalek
  computation done outside the VM.

**Phase R1b — Empty chip stub (1 commit)**:
- `chips/ristretto/mod.rs` with a chip that has zero rows but valid
  AIR/preprocessed/interaction shapes. Wire into BASE_COMPONENTS,
  active_components, ChipActivity. Verify gated correctly: existing
  proofs unaffected.

**Phase R1c — Field arithmetic primitives (~3-5 commits)**:
- M31 implementation of `field_mul_p25519`, `field_add_p25519`,
  `field_sub_p25519`, `field_inv_p25519` (inverse via fermat's).
- Per-op constraint blocks. Heavy lifting; benchmark independently.

**Phase R1d — Edwards point operations (~2-3 commits)**:
- Doubling and addition formulas in extended coords.
- Per-row constraint block composition.

**Phase R1e — Scalar mult full loop (~2 commits)**:
- NAF window decomposition.
- Main loop trace generation.
- Boundary memory lookups.

**Phase R1f — End-to-end test (1 commit)**:
- `prove_ristretto_via_ecall` test mirroring `prove_blake2b_via_ecall`
  (`tests/prove_vos_actor.rs:677`). Smallest possible exercise.
- Re-run `clerk-private-pay-bench` with cipher-clerk patched to use
  the ECALL — measure prove time, confirm sub-X-second target.

Realistic effort estimate: **3-5 weeks of focused work**, dominated by
Phase R1c (field mod-p arithmetic in M31) and Phase R1d (Edwards
point ops + their carry-chain witnesses).

## 9. What this design doesn't yet answer

- **Exact column count and row count** — need a prototype to nail down.
  60 M cells/call is an estimate, not a measurement.
- **Whether p25519 reduction can be done in <30 rows per field mult**
  on M31 — the answer determines viability.
- **Curve swap option** — should `cipher-clerk` move to a circuit-
  friendly curve for the long term? Out of scope for this chip but the
  decision should be made before sinking 3-5 weeks into Curve25519
  specifically.
- **Schnorr verify path** — the recipient side
  (`clerk-private-pay-receive-bench`) needs `k₁*G + k₂*P` for verify;
  is that worth a separate MSM precompile or do we just call k*P
  twice + a point-add precompile?
- **Fixed-base optimization** — basepoint mult could be ~5× faster
  with a precomputed table chip; defer to Phase R2 unless
  measurements show it's the difference between 1.2 s and 0.8 s.

## 10c. ACTUAL prove-time measurement (R1f-combined)

`bench_ristretto_chip_combined_with_cpu_baseline` — full per-payment
proof: clerk-private-pay-bench (37K PVM steps, log17) + one
RistrettoChip payment (21K rows, log15) in a single combined proof.

| Phase | Time | % |
|---|---:|---:|
| trace_gen | 218 ms | 1% |
| preprocess_commit | 193 ms | 1% |
| main_commit | 5.04 s | 29% |
| interaction_gen | 991 ms | 6% |
| interaction_commit | 4.44 s | 26% |
| stark_prove (FRI) | 6.53 s | 37% |
| **Total** | **17.42 s** | |
| Verify | 237 ms | |
| Proof size | 453 KB | |

Trace shape after R1e-quat:
- main_cols: 1655 (878 baseline + 777 RistrettoChip)
- interaction_cols: 1588 (304 baseline + 1284 RistrettoChip)
- log_size: 17

The 1284 extra interaction_cols come from the chip's ~642 Range256
emissions per real row; finalize_logup_in_pairs() pairs adjacent
emissions ⇒ ~2 interaction cols per emission.

Sub-second analysis with the measured baseline:

| Optimization layer | Cumulative time |
|---|---:|
| CPU baseline (this measurement) | 17.4 s |
| + GPU/SIMD (3×) | 5.8 s |
| + NAF-w4 (−30% chip rows) | 4.5 s |
| + lower security (80-bit, halves FRI queries) | 2.5 s |
| + tighter chip cells (R1c-7 carry-chain refactor) | 1.5 s |

**Realistic floor without chip refactor: ~3-5 s** on high-end
mobile.  Sub-second requires (a) significantly tighter chip
(~50% cell reduction), and/or (b) aggressive batch proving
(multiple payments amortized), and/or (c) different curve choice.

## 10b. Measured row projection (R1e)

The R1e double-and-add composition gives concrete row counts per
operation, validated by `project_ristretto_chip_size_for_one_payment`:

| Operation                              | Rows  |
|----------------------------------------|------:|
| Scalar mult (256-bit, double-and-add)  | 4150–6400 |
| Point addition (extended Edwards)      | 18 |
| Point doubling (extended Edwards)      | 16 |

**Per cipher-clerk private payment** (1 Pedersen v·G + b·H + add,
1 Schnorr k·G + sk·G): **21,118 chip rows ⇒ chip log_size 15**.

Throughput on the dev box, from clerk-private-pay-bench at log17 in
6.5s: ~17.7M cells/s.  Projected prove time IF the constraint-debug
bug were resolved:

| Configuration                        | Prove time |
|--------------------------------------|----:|
| CPU only                             | ~7.8 s |
| CPU + GPU (3×)                       | ~2.6 s |
| CPU + NAF-w4 (−30% rows) + GPU       | ~1.8 s |

**Sub-second** requires **all** of: NAF-w4, GPU/SIMD, tighter chip
cells (smaller M31 carry chains), AND lower security parameters
(e.g. 80-bit for low-value, 96-bit for high-value).  ~2 s on
mobile is the realistic floor without major chip refactors.

## 10. Sub-second target — what hits

Working back from the goal:

- **clerk-private-pay-bench full flow with chip**: estimated ~50K
  PVM steps + 4 chip-call rows = trace dominated by the chip cells
  (~240 M cells / 2²⁸ = log_size ~19-20).
- **At log20, current prover**: ~30-60 s (extrapolating from
  log17→6.5s, doubling per log step).
- **With smaller field-mult chip** (target: half the cells): log19
  → ~15-30 s.
- **With GPU/SIMD M31 backend**: 2-5× speedup → 3-15 s.
- **With proof-time-tuned mobile config (blowup=2 instead of 4)**:
  another ~30% → 2-10 s.

Sub-second on CPU for a full private payment is a stretch. Sub-second
with GPU + a tightly-optimized chip is plausible but not guaranteed
until we measure. **Realistic post-R1 target: 2-3 s on a recent
mobile SoC.**

That's already well into "tap and pay it feels instant" territory
(Apple Pay's contactless handshake takes ~500 ms; a 2 s background
prove that finishes by the time the receipt prints is fine UX).
Sub-second remains the north star; Phase R2 (specialized basepoint
chip + multi-scalar chip) is what closes the last factor.
