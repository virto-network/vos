# Phase I — Blake2bChip rewrite plan + degree audit

Phase G (pin bump + renames) and Phase H (block confirmed) are committed.
This document captures the constraint-degree audit for `Blake2bChip` and
the helper-column design needed to flatten it to
`LOG_CONSTRAINT_DEGREE_BOUND = 1` (algebraic degree ≤ 2). Future
sessions pick up here.

## Honest scope correction

The original migration doc estimated `Blake2bChip` at "~50 helpers, ~1
week". This audit finds **~235 helper columns** and a realistic effort
of **2–3 person-weeks** for the chip alone. The five-chip total likely
revises from "6–8 weeks" to **"10–14 weeks"** once the same audit is
done for `Mul`/`DivRem`/`Cpu`/`Ristretto`. The discrepancy comes from
constraints that were under-counted as "1 add_constraint call" but live
inside `for i in 0..8` (or `for k in 0..16`) loops emitting 8× / 16× /
128× more constraints than the call-count suggests. The chip emits
~830–1000 individual algebraic constraints, not 41.

## Constraint inventory by algebraic degree

`add_constraints` lives at `crates/zkpvm/src/chips/blake2b/mod.rs:76`.

### Already degree ≤ 2 (no helpers needed)
- **Step 1/3/5/7/8 byte-add identities** (`carry · 256` decomposition):
  `is_real * (a1[i] + carry1[i] · 256 - a_in[i] - b_in[i] - mx[i] -
  carry_in)` — `is_real` × linear combination = degree 2. ✓
- **`is_real * t_e[8+i]` zero-pad** (line 953): degree 2. ✓
- **`is_real * (d_out[i] - xor3_k)`** d_out reification (line 397):
  body is a linear combination of `d_in`, `a1`, `and1`, `a_out`, `and3`
  — all base columns. Degree 2. ✓

### Currently degree 3 (need 1 helper or gate-flatten)
- **Carry2/Carry4/Rot63Carry boundedness** (lines 380, 382, 384):
  `is_real * c · (c-1)` — degree 3. Need 1 helper per (c, byte index)
  = `c_squared := c · (c-1)`, then constraint becomes
  `is_real * c_squared` (degree 2) plus the helper-defining
  constraint `c_squared - c · (c-1) = 0` (degree 2).
  **Helpers: 24** (8 bytes × 3 carries).
- **F-bound** (line 633): `is_real * F · (F-1)` — degree 3. **Helpers: 1.**
- **a_in / b_in / c_in / d_in input-match** (lines 468–471): the body
  `Σ_j is_gidx[j] · v_cols[...][i]` is degree 2 (preprocessed × main).
  Wrapped in `is_real * (...)`, total degree 3. Strategy: introduce a
  per-byte sum helper:
  ```
  sum_a[i] := Σ_j is_gidx[j] · v_cols[G_INDICES[j][0]][i]   // deg 2
  is_real * (a_in[i] - sum_a[i])                            // deg 2
  ```
  **Helpers: 32** (4 inputs × 8 bytes).
- **Mx / My selection** (lines 587–588): identical pattern with
  `is_mx_slot[k]` / `is_my_slot[k]`. **Helpers: 16** (2 × 8 bytes).
- **V[14] init** (line 669): `init_gate * (v_cols[14][i] - (iv6_i +
  F · (255 - 2·iv6_i)))`. `iv6_i` is a constant, so the `F·(255 -
  2·iv6_i)` body is degree 1 in F. With `init_gate = is_real ·
  is_first` (degree 2) the total is degree 3. Use the gate helper
  below — no per-constraint sum helper needed.

### Currently degree 4 (need 2 helpers + gate-flatten)
- **Carry1 / Carry3 boundedness** (lines 366–377): `is_real * c · (c-1)
  · (c-2)` — degree 4. Need 2 helpers per (c, byte index):
  ```
  c_x_cm1 := c · (c-1)              // deg 2
  c_full  := c_x_cm1 · (c-2)        // deg 2 (helper × linear)
  is_real * c_full                  // deg 2
  ```
  **Helpers: 32** (8 bytes × 2 carries × 2 helpers).

### Currently degree 3 from gated body (need gate helper, reuse across many constraints)
The chip uses 4 distinct gates, each a product of two main/preprocessed
columns:
- `gate := is_real * (1 - is_last)` — V_next, m_cols inter-row,
  h_cols/t_e/f_e inter-row, h_ptr/m_ptr inter-row.
- `init_gate := is_real * is_first` — V[0..15] init derivations.
- `init_gate_8b := is_real * is_first` — same as `init_gate`; can share.
- `output_gate := is_real * is_last` — Phase 2b output derivation.
- `write_gate_8b := is_real * is_last` — same as `output_gate`; share.

Each gate is degree 2. When a gate multiplies a body that is itself
degree 1 (`gate * linear`), total is degree 3. Introduce 1 helper per
distinct gate:
- `gate_h - is_real * (1 - is_last) = 0` — degree 2 ✓.
- `init_gate_h - is_real * is_first = 0` — degree 2 ✓.
- `output_gate_h - is_real * is_last = 0` — degree 2 ✓.
- (Skip duplicates `init_gate_8b` and `write_gate_8b`; reuse.)

After the gate helpers, ALL gated constraints with linear bodies
(`gate_h * linear_body`) are degree 2. ✓

**Helpers: 3** (gate, init_gate, output_gate).

### Currently degree 3 from gated quadratic body (need sum helper + gate helper)
- **V_next update** (line 491): `gate * (v_cols_next[k][i] - Σ_j
  is_gidx[j] · contribution_j(k, i))`. Sum body is degree 2 (per-j
  product), gate is degree 2 ⇒ total degree 4 currently.
  Strategy:
  ```
  next_sum[k][i] - Σ_j is_gidx[j] · contribution_j(k, i) = 0   // deg 2
  gate_h * (v_cols_next[k][i] - next_sum[k][i])               // deg 2
  ```
  **Helpers: 128** (16 slots × 8 bytes).

### Linear gated bodies (just need gate helper, no sum helper)
- m_cols inter-row (line 595): 128 constraints, body is linear
  `m_cols_next - m_cols`. Reuse `gate_h`.
- h_cols inter-row (line 689): 64 constraints. Reuse `gate_h`.
- t_e / f_e inter-row (lines 695, 697): 17 constraints. Reuse `gate_h`.
- h_ptr / m_ptr / call_ts inter-row (lines 816–820): 16 constraints.
  Reuse `gate_h`.
- V[0..8] = H_k init (line 650): 64 constraints. Reuse `init_gate_h`.
- V[8..12] = IV[0..4] init (lines 655–658): 32 constraints.
  Reuse `init_gate_h`.
- V[12] / V[13] init (lines 661, 664): 16 constraints.
  Reuse `init_gate_h`.
- V[14] init (line 669): 8 constraints. Reuse `init_gate_h`.
- V[15] = IV[7] init (line 671): 8 constraints. Reuse `init_gate_h`.
- Address derivation (lines 841, 849, 857): 256 constraints.
  Reuse `init_gate_h`.
- Phase 2b output derivation (line 743): 64 constraints.
  Reuse `output_gate_h`.

## Total helper column count

| Category                     | Helpers |
|------------------------------|--------:|
| Carry1/Carry3 (degree-4 → 2) |      32 |
| Carry2/Carry4/Rot63 (deg-3)  |      24 |
| F-bound                      |       1 |
| Input-match (a/b/c/d)        |      32 |
| Mx / My selection            |      16 |
| V_next sum                   |     128 |
| Gate helpers (3 distinct)    |       3 |
| **Total**                    |   **236** |

For comparison: the chip currently has roughly 280 main-trace columns
(based on the wide `Column` enum with V[0..16] × 8 bytes + M[0..16] × 8
bytes + intermediate state columns). 236 helpers is **~85% column
inflation**, plausibly cancelling or exceeding the v2.x perf cluster's
10–30% gain — possibly a net regression for Blake2bChip in isolation.

## Implementation order for a future session

Once the work begins, do these subphases. **Caveat:** none of these is
independently validatable end-to-end (see "Validation gate is global"
section below). They pass `cargo check`; the chip runs the prove path
only after the *last* subphase of the *last* chip lands.

1. **I-blake2b-1** — add gate helpers (`gate_h`, `init_gate_h`,
   `output_gate_h`), update `Column` enum, fill them in
   `generate_main_trace`, replace gate sites in `add_constraints`.
   Smallest, lowest-risk change. After this, all linear-gated
   constraints are degree 2.
2. **I-blake2b-2** — add carry-bound helpers (32 + 24 = 56 columns).
   Witness-fill is mechanical (just `c · (c-1)` and `c_x_cm1 · (c-2)`).
3. **I-blake2b-3** — F-bound helper (1 column). Trivial.
4. **I-blake2b-4** — input-match sum helpers (32 columns). Witness-fill
   mirrors the same `Σ_j is_gidx[j] · v_cols[...]` computation already
   done implicitly in the prover. Add a `sum_a/b/c/d` array fill in
   `generate_main_trace` that mirrors the active-G slot.
5. **I-blake2b-5** — Mx/My sum helpers (16 columns). Same pattern.
6. **I-blake2b-6** — V_next sum helpers (128 columns). Highest-risk
   subphase: 128 column entries per row × 96 rows per compression.
   Verify chip-isolated test passes.
7. **I-blake2b-7** — final integration: re-run
   `profile_clerk_private_pay_bench` and capture the column-count and
   prove-time delta vs. the 3.85 s baseline. Document in BENCHMARKS.md.

Commit per subphase.

## Risks and watch-points

- **Witness/constraint mismatch is the main soundness landmine.** The
  helper columns must be filled with *exactly* the same algebraic
  expression the constraint expects. A subtle bug — wrong index, off-
  by-one in the byte permutation, gate firing on the wrong row —
  produces a chip-isolated test that *passes* (because both sides have
  the same bug) but a verifier that silently accepts unsound proofs.
- **`is_first` and `is_last` are preprocessed**, so the gate helpers
  cost 3 main-trace columns × all rows but the values for those columns
  must be filled to the *product* of the corresponding preprocessed
  values × the runtime `is_real`.
- **Watch `LOG_CONSTRAINT_DEGREE_BOUND` declaration**: drop from `2` to
  `1` only at the *very end*, after the chip-isolated test passes at
  the current bound. Lowering the declared bound first triggers the
  framework's actual-degree check before the helpers are wired.

## Critical: validation gate is global, not per-chip

The Stwo lifted-protocol restriction is over the **whole AIR**, not
individual components. Confirmed by Stwo's own Poseidon `#[ignore]`:
the test ignores even a single-component prove because the
*combined* AIR (preprocessed + main + interaction across the one
component) has constraint degree ≥ 2.

Concrete consequence for our migration: we have no per-chip
validation gate. Specifically:

- `BASE_COMPONENTS[0] = CpuChip` is always-active (`is_active` returns
  `_ => true`); every `prove` call pulls it in. CpuChip has
  `LOG_CONSTRAINT_DEGREE_BOUND = 2`. Until CpuChip is flattened, no
  prove path completes — even one whose `side_note` only triggers
  Blake2b activity, because the ECALL step itself is a CpuChip row.
- Likewise, even a hypothetical chip-isolated harness running
  `Blake2bChip` alone would fail until all of its constraints are
  ≤ degree 2. There's no way to land "Blake2bChip done, MulChip
  pending" and validate Blake2bChip via the prove path.

This contradicts the audit doc's "Commit per subphase" cadence and
the original migration prompt's "Run [bench] after every chip is
migrated" guidance. Both assumed per-chip validation was possible;
it isn't.

**Implications for the rewrite cadence:**

- Per-subphase commits are *structural-only*: they pass `cargo
  check` but no test validates them until the *final* subphase of
  the *last* chip lands. That's a 10–14 week trust-the-algebra
  window where a subtle witness/constraint mismatch would be
  invisible.
- One-big-commit bundling all 5 chips (≈ thousands of helper
  column entries spread across the witness fill code, plus a
  matching constraint refactor) is hard to review.
- The honest alternative: build a **chip-isolated prove harness**
  before starting the rewrites. That requires (a) a `prove` variant
  taking an explicit component list, (b) a `side_note` builder that
  only triggers the chip under test, and (c) accepting that lookup
  balance won't close (Blake2b emits to MemoryChip, BitwiseLookup,
  Range256, Blake2bCallLookup — all of which need producers in scope
  to balance). Probably 1–2 weeks of harness work *before* a single
  chip rewrite line is written. Pays back many times across the 5
  chips, since each gets independent validation.

**Strongly recommended:** do the chip-isolated prove harness as
Phase I.0 before starting subphase 1 of any chip rewrite. The
upfront cost is small relative to the downstream debugging cost of
trusted-blind rewrites.

## Stopping point for this session

This audit is the deliverable. Phases G + H are committed. Code changes
to the chip itself are deferred to a session with multi-week scope.
The next session should:

1. Read this doc.
2. Verify Phase G's pin still applies (`grep e1286720 Cargo.toml`).
3. Run `cargo test -p zkpvm --features prover --release --test
   phase2_alu prove_add64` — should reproduce
   `ConstraintsNotSatisfied`.
4. Start I-blake2b-1.

When MulChip is started, do a similar audit pass for it — its 16
constraints over 64-bit schoolbook multiply are likely simpler than
Blake2bChip per-constraint but still need this same gate-and-sum
helper analysis.

## Strategic option to revisit

If the corrected scope (10–14 weeks for all 5 chips) is heavier than
the user wants to commit to, an alternative:

- **Stay on `0790eba` (current proven baseline, 3.85 s prove)** as
  long as the existing tests stay green.
- **File the upstream issue** (draft at
  `STWO_UPSTREAM_ISSUE_DRAFT.md`) to get a Stwo-team timeline on
  degree-≥2 in the lifted protocol. If the answer is "next quarter"
  the migration becomes 1 week of path renames again.
- **Re-check upstream every 2–4 weeks** rather than sinking 10+ weeks
  into chip rewrites that will be obsoleted once upstream lands.

This is a strategic decision for the user, not a technical one
inherent to the migration. Surface it explicitly before sinking the
next 1–2 weeks into Blake2bChip-1.
