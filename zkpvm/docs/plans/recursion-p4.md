# P4 build plan: the assembled join-AIR, the fixed point, and the build spike

Status: **IN PROGRESS (2026-06-17).** Branch `voucher-state-transition`. Builds on
the four GREEN P3 verifier-AIR chips (`channel_chip.rs`, `fri_fold_chip.rs`,
`oods_composition_chip.rs`, `merkle_decommit_merged.rs`) + the integrated
log_size-14 measurement (`verifier_air_integration.rs`). Reads on
`recursion-design.md` (the lift→join architecture) — this doc is the concrete,
source-grounded P4 build sequence.

All `verifier.rs`/`fri.rs`/`pcs/*`/`vcs_lifted/*` line numbers below are in the
stwo checkout the workspace pins (rev `e1286720`):
`~/.cargo/git/checkouts/stwo-59e22971a65c0edb/e128672/crates/stwo/src/core/`.

---

## The verify flow the join-AIR must arithmetize (the spec)

A stwo verify is `verify_ex` (`verifier.rs:35`) then `verify_values`
(`pcs/verifier.rs:59`). The Fiat-Shamir order is load-bearing (soundness), so
the in-AIR replay must follow it exactly. Chip assignment:

| # | Step (stwo source) | vos chip | Real proof data consumed |
|---|---|---|---|
| A1 | caller commits preprocessed / main / interaction trees: `mix_root` each (`pcs/verifier.rs:43-57`) | **ChannelChip** | `commitments[0..k]` (each a hash → absorbed as 8×M31) |
| A2 | `random_coeff = draw_secure_felt()` (composition coeff) (`verifier.rs:78`) | **ChannelChip** (squeeze) | — drawn |
| A3 | commit composition tree (`verifier.rs:81`) | **ChannelChip** | `commitments.last()` |
| A4 | `oods_point = get_random_point(channel)` (`verifier.rs:88`) | **ChannelChip** (squeezes) | — drawn |
| B1 | DEEP-ALI: `composition_oods_eval == eval_composition_polynomial_at_point(...)` (`verifier.rs:105-120`) | **OodsCompositionChip** | `proof.sampled_values` (mask evals at OODS) |
| B2 | `mix_felts(sampled_values.flatten_cols())` (`pcs/verifier.rs:65`) | **ChannelChip** | sampled values |
| B3 | `random_coeff = draw_secure_felt()` (DEEP coeff) (`pcs/verifier.rs:66`) | **ChannelChip** (squeeze) | — drawn |
| C1 | `FriVerifier::commit`: mix first-layer root → draw α₀; per inner layer: mix root → draw αᵢ; `mix_felts(last_layer_poly)` (`fri.rs:113-187`) | **ChannelChip** | FRI layer commitments + `last_layer_poly` coeffs |
| C2 | `verify_pow_nonce(pow_bits, proof_of_work)` then `mix_u64(proof_of_work)` (`pcs/verifier.rs:76-79`) | **ChannelChip** (pow rows + difficulty bit-decomp) | `proof.fri_proof` PoW nonce |
| D1 | `sample_query_positions = draw_queries(channel, first_layer_log, n_queries)` then `Queries::new` SORT+DEDUP (`fri.rs:294-300`, `queries.rs:11/41`) | **ChannelChip** drives `draw_u32s`; positions = the query schedule | — drawn |
| E1 | per-tree `MerkleVerifierLifted::verify(query_positions, queried_values, decommitment)` (`pcs/verifier.rs:104-116`, `vcs_lifted/verifier.rs:103`) | **MerkleDecommit** (one uniform component) | `proof.decommitments` (hash witnesses) + `queried_values` |
| E2 | `fri_answers(...)` = per-query DEEP quotient accumulation (`pcs/verifier.rs:126`, `quotients.rs:120/162`) | **DEEP-quotient chip (NEW)** | queried column values + OODS samples + coeffs |
| F1 | first layer circle→line fold + Merkle-verify reconstructed subset (`fri.rs:235-259`, `SparseEvaluation::fold_circle` `fri.rs:712`) | **FriFoldChip** (circle) + **MerkleDecommit** | first-layer evals, `fri_witness` siblings, α₀ |
| F2 | inner-layer loop: `fold_line` + Merkle-verify each layer (`fri.rs:261-265`, `523-589`, `fold_line` `fri.rs:746`) | **FriFoldChip** (line) + **MerkleDecommit** per layer | each layer commitment, αᵢ, `fri_witness` |
| F3 | last layer: `query_eval == last_layer_poly.eval_at_point(x)` (`fri.rs:282-288`) | **last-layer-eval chip (NEW, small)** | `last_layer_poly`, surviving query evals |

The OODS composition re-eval (B1) embeds **every inner-AIR constraint** — for a
real canonical conservation segment that is all 31 components (~530
`add_constraint` sites); for P4.1's de-risk child it is the child's small AIR.

---

## P4.1 — Assemble the chips against ONE real child proof

P3 tested each chip in isolation against *representative* witness columns
(e.g. `fri_fold_chip.rs` takes `itwid` as a **free** column; `oods_composition`
extracts real data but stands alone). P4.1 drives all four chips off **one
`ChannelChip` transcript replay against one real `Proof`** produced under the
Poseidon2-M31 stack, reusing `oods_composition_chip.rs::extract_oods` as the
template for feeding each sub-chip the proof's real data.

The de-risk child for P4.1 is a SMALL real Poseidon2-M31 proof (the
`oods_composition_chip.rs::prove_inner` `a·b / a·inv` AIR, or the
`channel_chip.rs::prove_representative` 2-component logup proof) — NOT yet the
full 31-component conservation segment (that needs Stage-0 re-proving under
Poseidon2-M31, which is P5). The point of P4.1 is to prove the WIRING works on
**real** proof data end-to-end: ACCEPT a valid child, REJECT a tampered
query/sample/path.

### New chips P4.1 needs (not yet built)

1. **DEEP-quotient chip** (`fri_answers` / `accumulate_row_quotients`,
   `quotients.rs:162`) — the bridge from trace `queried_values` at each query
   position to the first-layer FRI evals. Per query position `p`:
   `Σ_batches Σ_cols (queried·c − (a·p.y + b)) · denom_inverse`, where
   `(a,b,c)` are the complex-conjugate line coeffs through `(sample_point,
   sample_value)` (`quotients.rs:223 column_line_coeffs`,
   `constraints.rs::complex_conjugate_line_coeffs`) and `denom_inverse ∈ CM31`
   is the line-through-conjugate quotient (`quotients.rs:253`). Pure QM31/CM31
   field arithmetic, witnessed products — the `oods_composition`/`qm31_constraints`
   idiom (degree ≤ 2). **This is the most tractable missing piece — build it
   first, gated against real `fri_answers` output extracted via the
   `extract_oods` transcript-replay pattern.**

2. **Multi-tree / cross-layer MerkleDecommit driver.** `merkle_decommit_merged.rs`
   re-hashes ONE simple path. The real proof has 4 commitment trees (preproc,
   main, interaction, composition) of different heights + one Merkle tree per FRI
   layer. With mobile `FriConfig(0,2,38,1)` → `fold_step = 1` → `pack_leaves =
   false` → `LOG_PACKED_LEAF_SIZE` path is OFF (`fri.rs:124,168`), so each leaf is
   just the row of column values at a single position (simplest case — the build
   was scoped around mobile). The leaf is `update_leaf(row)` then `finalize`
   (`vcs_lifted/verifier.rs:145-147`); internal nodes `hash_children`. Sibling
   chunking + witness logic at `vcs_lifted/verifier.rs:157-181`.

3. **Cross-layer FRI fold chaining.** `fri_fold_chip.rs` folds ONE pair.
   The real verifier folds each query across ~`mlbd` layers, halving the query
   index each layer (`Queries::fold`, `queries.rs:53`). There is NO explicit
   `layer_{k+1}[pos] == fold(layer_k pair)` equation in stwo — consistency is
   IMPLICIT via three coupled facts the join-AIR must wire together:
   (i) `folded = fold(pair)` for queried positions (FriFoldChip),
   (ii) `folded` becomes the next layer's eval at `q >> fold_step` (wiring),
   (iii) the reconstructed next-layer leaf (queried evals + `fri_witness`
   siblings) hashes into the next-layer Merkle root (MerkleDecommit).

4. **Last-layer eval chip** (small): `query_eval == last_layer_poly.eval_at_point(x)`
   (`fri.rs:282-288`) — a Horner poly eval over the surviving query positions.

### The three WIRING GAPS (the hard sub-problems)

- **GAP 1 — query-position → leaf-index plumbing.** Two index spaces co-exist:
  a drawn query `q` IS the Merkle leaf index (bit-reversed order); the geometric
  domain point is at NATURAL index `bit_reverse_index(q, log_size)` (`utils.rs:79`,
  used at `fri.rs:283,760,809`). The join-AIR must derive, in-circuit from the
  drawn `q`: the decommitment subset `subset_start..subset_start + 2^fold_step`,
  `subset_start = (q>>fold_step)<<fold_step` (`fri.rs:611-614`), AND the FriFold
  twiddle via `bit_reverse_index(q<<FOLD_STEP, log)` → `domain.at()` → `.inverse()`
  (line) / `.y.inverse()` (circle).
  **The twiddle half is DE-RISKED ✅ (2026-06-18, commit 11baf35,
  `tests/fri_twiddle_chip.rs`):** since `Coset::at(j) = (initial_index +
  step_size·j).to_point()` and `to_point` is a group hom,
  `domain_point(q) = initial + Σ_{q_k=1} (step_size·2^{L-1-k}).to_point()` — a
  bit-selected sum of L FIXED coset points. Adding a constant point is degree 1;
  the per-bit select is degree 2; so the twiddle is a depth-L chain of degree-2
  conditional point-adds + a witnessed inverse, derived from the bound query bits
  (no free column, no scalar-mult circuit). GREEN for all 32 indices vs stwo
  `domain.at(bit_reverse(q)).inverse()`. The remaining GAP-1 work is the
  subset/leaf-index bookkeeping (`q>>fold_step`, `subset_start`) wired into the
  Merkle decommit (gates 2+3), which is integer shifts on the same query bits.
- **GAP 2 — fold-consistency is the (i)+(ii)+(iii) coupling above**, not one
  equation. Wire all three or it is unsound.
- **GAP 3 — last-layer poly eval (chip 4 above)** closes the FRI tail.

### P4.1 incremental gates (each GREEN before the next)

1. **DEEP-quotient chip** — ✅ **DONE (2026-06-18, commit 6cd544b)**,
   `tests/deep_quotient_chip.rs`: `accumulate_row_quotients` arithmetized in-AIR
   over a real proof's OODS batch (complex-conjugate line coeffs + α-power chain
   + CM31 denom, all witnessed, degree ≤ 2), matching stwo's own
   `accumulate_row_quotients`; prove+verify; perturbed queried value rejected.
   (Per-batch demo; full multi-tree/all-query aggregation is the assembly.)
2. **Cross-layer FRI fold chain** — fold one real proof's FRI across all layers,
   query indices halving, each `folded` feeding the next layer; reject a
   perturbed fold. **GAP 1 (the twiddle) is now de-risked** — see below.
3. **Multi-tree Merkle decommit** — verify the 4 trace trees + per-layer FRI
   trees against the proof's real decommitment witnesses; reject a tampered path.
4. **Assemble** (1)+(2)+(3)+ChannelChip+OODS in ONE uniform component verifying
   a real small child proof end-to-end: ACCEPT valid, REJECT tampered
   query/sample/path.

**DONE (2026-06-17, commit 4c6c901):** the `verify_pow_nonce` difficulty
bit-decomp — previously the only deferred ChannelChip item. The pow2 perm
output `s2[0]` is bit-decomposed (31 booleans, weighted-sum == `out[0]` gated by
`is_pow2`), and the low `POW_BITS` (=20) bits are forced to zero — so PoW
difficulty is now enforced in-AIR (step C2 above), not just bound. Gates:
`channel_chip_{air_satisfied,gate}` (honest) + `channel_chip_pow_difficulty_enforced`
(a valid-but-sub-threshold pow2 perm is rejected — the difficulty constraint
bites). Folds into the assembled verifier for free.

---

## P4.2 — The fixed point (verify 2 children + seam + allowlist)

### Seam
`SegmentState` (`proof.rs:126-140`): `pc:u32`, `timestamp:u64`,
`registers:[u64;13]` (φ9..φ12 = io-hash window), `memory_commitment:[u8;32]`
(UNBOUND/vestigial — blake3, never FS-mixed), `memory_root:[u8;32]` (page-Merkle,
bound in-circuit). The chain seam `child_L.final_state == child_R.initial_state`
is full struct-eq today (`verifier/src/lib.rs:429,504`) but only
`{pc, timestamp, registers, memory_root}` are cryptographically bound.
**Join-AIR: equate only the four bound fields in-circuit; treat
`memory_commitment` as opaque pass-through** (struct-eq on an unbound field is
zero-soundness constraints).

### Allowlist + public inputs
Per-segment identity = `proof.stark_proof.commitments[0]` (preprocessed root;
`Blake2sHash` today, becomes `P2Hash`=8×M31 under the Poseidon2-M31 stack).
Membership = 2-way equality vs `{C_0, C_1}` (`verifier/src/lib.rs:513-521`;
baked `VOUCHER_CHECK_COMMITMENTS`, `prover/src/lib.rs:504-519`). The join-AIR
exposes as public inputs:
1. `expected_initial_root` (anchor) = leftmost child `initial_state.memory_root`,
2. `final_memory_root` = rightmost child `final_state.memory_root`,
3. `io_hash` = rightmost child `registers[9..13]` (`Proof::public_io_hash`,
   `proof.rs:210`) — threads up the tree for free,
4. allowlist identity — each child carries its primary commitment as a public
   input; the join checks it ∈ `{C_0,C_1}` (2-way eq) and exposes a hash of the
   set upward (public-input-hash form → changeable without a new circuit).

The boundary chips' claimed-sum recomputation (`boundary_binding.rs:116`, FS-mix
order `verifier/src/lib.rs:261-279`) is part of the embedded inner AIR the join
re-runs, so the four fields become *bound* public inputs automatically.

### The central question — does the join's OWN proof re-verify at log_size ≤ ~19?
**YES, MEASURED, ~4 bits of margin.** The verifier-AIR is ~99.5% perms, so
log_size = `ceil(log2(#perms))`. One child = 15.3K perms = **log 14** (proven at
the real 16K scale, `perm_scale.rs`/`verifier_air_integration.rs`, 515 cols/row,
degree ≤ 2). A join verifies 2 children ≈ 2×2^14 = 2^15 = **log 15**. Seam (4
field eqs) + allowlist (2-way eq) are negligible field-arith (width, not depth).
log 15 ≤ canonical ~19 ⇒ the fixed point CLOSES: a log-15 join is itself a child
of the next-level join at the same shape; 2×(log-15) ≈ log 16, still < 19. The
76-leaf / 75-join / depth-7 tree never exceeds the cap.

### Shape decision: ONE uniform AIR, no lift-wrapper
The producer/consumer SPLIT shape is REAL-broken under stwo's lifted-protocol
OODS (multi-component `ConstraintsNotSatisfied` on a clean build — a residual
custom-stack bug, NOT a soundness gap). The proven shape is one uniform
`FrameworkEval` (perm inline, `parent` chained directly, no interaction tree),
GREEN at the integration scale. Build the join the same way: perm workhorse =
row driver; FriFold/OODS/DEEP-quotient/Merkle/seam = additional columns on the
same rows. If a shared perm *producer* ever becomes necessary, do NOT split —
instrument `prove_ex` via the `olanod/stwo` fork `[patch]` (cargo fingerprints
git-dep stwo by rev, so editing the `.cargo` checkout never relinks). On any
inexplicable `ConstraintsNotSatisfied`, `cargo clean -p stwo` FIRST.

---

## P4.3 — wasm32 / PVM verify-only build spike  ✅ wasm32 GREEN

Crate `zkpvm/recursion-verifier/` — its OWN `[workspace]` (in the vos root
`exclude` list), pinning `stwo` + `stwo-constraint-framework` at the same rev
`e1286720` with **`default-features = false`** + `num-traits`/`serde`
(no_std). Carries the verify-side Poseidon2-M31 channel/hasher/`eval_permutation`
(promoted from `recursion_common`) + a concrete `verify_segment` that
monomorphizes `stwo::core::verifier::verify::<P2MerkleChannel>` — so building it
for a target compiles the WHOLE verify path for the custom M31-algebraic stack.

### Result
- **`cargo build --target wasm32-unknown-unknown` → GREEN.** The verify-only
  Poseidon2-M31 verifier compiles for wasm32 (the Substrate-pallet fallback
  venue, co-equal in `recursion-design.md`). Confirmed: **no blst, no rayon, no
  javm** in the dependency tree (`cargo tree -i` empty for all three) — the
  design doc's primary worry is ELIMINATED. The blst leak only ever entered via
  `zkpvm → javm` (non-optional, `zkpvm/Cargo.toml:22`), which this crate does not
  depend on; rayon only via stwo's `parallel` feature (off here).
- **PVM (`riscv64em-javm`, os:none) — BLOCKED, blocker characterized (NOT
  blst/rayon).** Two layers:
  1. *(easy, validated)* upstream stwo pulls `dashmap` (line 57),
     `tracing-subscriber` (line 54), and default `rand` (line 42)
     UNCONDITIONALLY — all need `std`, which os:none lacks (wasm32 has a partial
     std, hence it builds). `dashmap` is used only in `prover/` (feature-gated)
     and `tracing-subscriber` only in `tracing/` (feature-gated), so gating them
     behind `prover`/`tracing` + `rand default-features=false` in the stwo fork
     DROPS them from a `default-features=false` build. *Validated by a probe:
     after the gate, the tree has no dashmap/once_cell/tracing-subscriber.*
  2. *(the real wall)* the os:none target has `max-atomic-width: 0`, so
     `core::sync::atomic::{AtomicUsize,AtomicBool,AtomicPtr,AtomicU8}` and
     `alloc::sync::Arc` do not resolve, and stwo's verify graph
     (`hashbrown → foldhash`, `tracing-core`, `Arc`) uses them. This is the same
     class the vos messenger solved with **`portable_atomic`** (single-core
     assumption — valid since the PVM target is `singlethread: true`). Closing it
     needs portable_atomic routing across stwo's transitive deps (gate
     hashbrown's foldhash hasher, stub/gate `tracing`, replace `Arc` with
     `portable-atomic-util::Arc`) — or an atomics-capable PVM target variant
     (`+a` extension, if JAM PVM permits). `tracing-core` also showed a
     `no field next on Callsite` version skew under the rolling-nightly build-std.

### Remaining PVM work (precise)
1. Land the stwo-fork dep-gating (dashmap→`prover`, tracing-subscriber→`tracing`,
   rand `default-features=false`) — small, validated; commit it on the fork.
2. portable_atomic plumbing for the no-atomics target (the multi-crate effort),
   OR adopt a `+a` PVM target if the JAM PVM spec allows atomic instructions.
The wasm32 path is already a complete settlement-verify venue (Substrate pallet),
so this is the JAM-refine optimization, not a blocker for the recursion math.

### Build commands
```
# wasm32 (GREEN):
cargo build --release --target wasm32-unknown-unknown
# PVM (blocked, see above):
cargo +nightly build --release --target riscv64em-javm.json \
  -Zbuild-std=core,alloc,compiler_builtins -Zbuild-std-features=compiler-builtins-mem
```

---

## Sequencing after P4

- **P5** — tree driver (level-0 = 38 parallel leaf joins) + re-prove the 76 real
  segments under Poseidon2-M31 (recompute `{C_0,C_1}`) + wire `verify_aggregate`.
- **P6** — JAM/Substrate settlement verify + gas/size profile (needs the PVM
  atomics work above for the JAM-refine venue; the Substrate wasm venue is ready).
