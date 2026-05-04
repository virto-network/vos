# RistrettoChip — Curve25519 / Ristretto255 scalar mult precompile

**Status**: design proposal, no code yet.
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
