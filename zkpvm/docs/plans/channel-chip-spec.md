# ChannelChip spec — in-AIR Poseidon2-M31 Fiat-Shamir transcript replay

Status: **SPEC (2026-06-17).** Branch `voucher-state-transition`. Next P3 build
after the decommit un-block + the log_size measurement (both GREEN). This is the
chip that drives every challenge the rest of the verifier-AIR consumes.

## Goal + green gate

The verifier-AIR must replay, in-AIR, the exact Fiat-Shamir transcript the native
stwo verifier runs over the **custom Poseidon2-M31 channel** (`recursion_common::
Poseidon2M31Channel`), reproducing every drawn challenge:
`random_coeff` (composition), `oods_point`, the DEEP `random_coeff`, the per-layer
FRI `fold_alpha`s, the PoW check, and the query positions. Those outputs feed the
OodsComposition, FriFold, and MerkleDecommit chips.

**GREEN GATE:** an in-AIR replay over a *real* canonical segment proof's transcript
produces challenges bit-identical to the host `Poseidon2M31Channel` running the
same sequence. (Negative: perturb one absorbed value ⇒ a downstream challenge
diverges ⇒ rejected.) The transcript replay is ~**397 perms** (the cost-model's
tertiary term; FRI Merkle decommit at ~8.7K perms still dominates).

## The exact transcript sequence (cite as you build)

For a canonical segment proof *with* a logup interaction tree. Order matters —
this is what the in-AIR replay must match. Sources: stwo `core/verifier.rs:78-121`,
`core/pcs/verifier.rs:43-81`, `core/pcs/mod.rs:48-70` (`PcsConfig::mix_into`),
`core/fri.rs` (`FriVerifier::commit` / `sample_query_positions`), and the zkpvm
caller `zkpvm/verifier/src/lib.rs` (the preproc/main/interaction commits + logup
relation draw + claimed-sum mix).

1. `config.mix_into(channel)` — absorb 2 packed config felts (pow_bits,
   log_blowup, n_queries, log_last_layer, fold_step, lifting). [`pcs/mod.rs:48`]
2. `mix_root(preprocessed_root)` — absorb 8 M31. [PREPROCESSED_TRACE_IDX=0]
3. `mix_root(main_root)` — absorb 8 M31.
4. Draw the **logup relation challenges** (`draw_secure_felt` per relation /
   `Relation::draw`) — these are the interaction-trace challenges.
5. `mix_felts(claimed_sums)` — absorb the per-component claimed sums.
6. `mix_root(interaction_root)` — absorb 8 M31.
7. `random_coeff = draw_secure_felt()` — **composition combination randomness**.
   [`verifier.rs:78`]
8. `mix_root(composition_root)` — absorb 8 M31. [`verifier.rs:81`, last commitment]
9. `oods_point = CirclePoint::get_random_point(channel)` — **one `draw_secure_felt`
   + the stereographic map** `x=(1-t²)/(1+t²), y=2t/(1+t²)` (`circle.rs:169`).
10. `mix_felts(sampled_values.flatten_cols())` — absorb ALL OODS sampled values
    (per-tree, per-column). **Bulk term**: ~640 columns ⇒ the largest absorb.
    [`pcs/verifier.rs:65`]
11. `random_coeff_deep = draw_secure_felt()` — **DEEP/line-batch randomness**.
    [`pcs/verifier.rs:66`]
12. `FriVerifier::commit`: for each of the ~19 inner layers — `mix_root(layer_root)`
    then `fold_alpha = draw_secure_felt()`; then `mix` the last-layer poly coeffs.
13. `verify_pow_nonce(pow_bits=20, proof_of_work)` — the PoW check (see below).
    [`pcs/verifier.rs:76`]
14. `mix_u64(proof_of_work)` — absorb the nonce as 2 M31. [`pcs/verifier.rs:79`]
15. `query_positions = sample_query_positions(channel)` — `draw_u32s` (one
    `squeeze8` → 8 u32 per call, as many as needed for 38 queries). [`fri.rs`]

## Custom-channel op → perm mapping (`recursion_common::Poseidon2M31Channel`)

Each op is a sequence of width-16 Poseidon2-M31 permutations on the 8-M31 `digest`
+ 8-M31 rate; the in-AIR chip constrains one perm per sponge step and threads the
digest:

- `absorb(values)`: for each RATE(=8) chunk — `state[0..8]=digest`,
  `state[8+i]+=chunk[i]`, **permute**, `digest = state[0..8]`. Empty values ⇒ one
  permute. (⇒ `ceil(len/8)` perms, ≥1.)
- `squeeze8()`: `state[0..8]=digest`, `state[8]=n_draws`, `state[9]=DRAW_DOMAIN(3)`,
  **permute**, output `state[0..8]`, `n_draws+=1`. (1 perm; n_draws resets to 0 on
  the next `update_digest`.)
- `mix_root` = `absorb(root.0)` (1 perm). `mix_felts` = absorb `to_m31_array`s.
  `mix_u64` = absorb 2 M31. `draw_secure_felt` = `squeeze8`, take `[0..4]`.
  `draw_secure_felts(n)` = `squeeze8` ×⌈n/2⌉ (2 per squeeze). `draw_u32s` =
  `squeeze8`, the 8 limbs.

## Chip structure (one-uniform-component design)

The whole verifier-AIR is ONE uniform component (the decommit un-block established
this; the producer/consumer split is the blocked path). The channel replay is a
**sequence of perm rows with digest chaining**:

- **One sponge perm per row.** Columns: the width-16 perm trace (reuse
  `recursion_common::eval_permutation`, 442 cols/perm) + a few control columns
  (the absorbed chunk / `n_draws` / `DRAW_DOMAIN` injected into the rate half; the
  output digest slice).
- **Digest chaining:** `digest_in(row k+1) == digest_out(row k)` — a cross-row
  constraint (next-row mask) OR a selector-gated transition. The digest is
  `perm_input[0..8]`; for absorb rows the rate `perm_input[8..16] = prev_digest_rate
  + absorbed_chunk`; for squeeze rows `perm_input[8] = n_draws`, `[9] = 3`.
- **Challenge outputs:** the drawn challenges are `perm_output[0..4]` (as QM31) of
  the squeeze rows; constrain them equal to the values the FriFold/Oods/Decommit
  chips consume (those chips reference these columns directly — intra-component, no
  cross-chip relation, matching the decommit's inline binding).
- **Absorbed data binding:** the absorbed roots are the proof's commitment roots
  (public inputs / committed columns); `mix_felts(sampled_values)` absorbs the OODS
  values that the Oods chip also uses — bind them to the same columns.

Because it's one component, the channel perms are just more rows in the same
perm-dominated trace (already counted in the ~16K). No interaction tree needed
(clean-build single-component proves fine — see `merkle_decommit_merged.rs`).

## `verify_pow_nonce` arithmetization (`recursion_common` lines ~283-294)

Host does: `s = permute(digest ‖ n_bits)`, `s2 = permute(s[0..8] ‖ nonce_lo ‖
nonce_hi)`, then asserts `s2[0].trailing_zeros() >= n_bits` (n_bits=20). In-AIR:
- 2 perm rows (the two permutes), digest/n_bits/nonce as inputs.
- Bit-decompose `s2[0]` (an M31, 31 bits): witness 31 boolean bits, constrain
  their weighted sum == `s2[0]`, and constrain the low `n_bits` (=20) bits are all
  zero. (n_bits is a public constant ⇒ no range gymnastics; just 20 booleans=0.)

## Build order + gotchas

1. Start with a **host-side replay test**: run `Poseidon2M31Channel` through the
   exact sequence above on a real `prove_canonical` proof, recording every
   `(absorb input, squeeze output)`. This is the ground truth the AIR must match
   and pins the exact op order (resolve any caller-order ambiguity here first).
2. Then the AIR: digest-chaining + squeeze-output constraints, reusing
   `eval_permutation`. Gate: AIR satisfied on the recorded trace (AssertEvaluator),
   then prove+verify through the lifted protocol (single component, clean build).
3. **Clean-build gotcha:** on any inexplicable `ConstraintsNotSatisfied`,
   `cargo clean -p stwo` first (a stale rlib produced a phantom blocker once — see
   `merkle_decommit_merged.rs` module doc).
4. Degree ≤ 2 (witnessed S-box keeps perms degree 2; bit-decomp is degree 2);
   `max_constraint_log_degree_bound = log+1`.
5. The exact `sampled_values` flatten order (`flatten_cols`) must match between the
   host replay and the AIR column layout — verify against the real proof in step 1.

## After ChannelChip

→ **FriFoldChip** (QM31 ibutterfly per query/layer, using the `qm31_constraints.rs`
witnessed-mul/inverse idiom; consumes `fold_alpha`s + query positions from here)
→ **OodsCompositionChip** (re-eval the 31-component inner AIR at `oods_point`;
consumes `random_coeff` + sampled_values) → integrate all into the one uniform
verifier-AIR → re-measure log_size (should hold ~14).
