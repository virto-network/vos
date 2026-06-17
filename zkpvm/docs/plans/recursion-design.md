# Recursive aggregation design: fold the conservation chain into one proof

Status: **DESIGN (2026-06-17).** Branch `voucher-state-transition`. Supersedes
the "approach C" sketch in `recursion-spike.md` with a concrete, grounded build.
Reads on: the cross-node delivery is already solved by the per-segment manifest
(`federation-wire-through.md`); recursion is for the **on-chain settlement**
goal — one verifiable proof a JAM service (or Substrate runtime) checks. The
chain is Substrate/JAM, NOT EVM, so a STARK is verified directly (no SNARK wrap).

## Goal

Replace the N=76-segment `verify_chain_standalone_allowlist` + io-binding with a
single `verify_aggregate(expected_initial_root, final_memory_root, io_hash,
allowlist)` over ONE constant-size aggregate proof (~1–2 MiB), verified in a JAM
refine service.

## Foundation (de-risked)

`zkpvm/tests/poseidon2_pcs_spike.rs` (GREEN) proved the substrate: a custom
**Poseidon2-over-M31** `MerkleHasherLifted` + `MerkleChannel` proves+verifies on
stwo's CpuBackend with no source edits (lifted backend ops are blanket; one
orphan-legal `BackendForChannel` marker). The inner proofs can be committed under
an M31-algebraic hash → their Merkle decommitment paths are cheap to re-verify
in-AIR. (The spike's *transcript* is still Blake2sM31; an M31-algebraic transcript
is P1 below.)

## Architecture (RISC-Zero lift→join model)

- **Stage 0 (prereq):** re-prove each of the 76 conservation segments under a
  Poseidon2-M31 Merkle channel **and** Poseidon2-M31 Fiat-Shamir transcript →
  a new 2-entry canonical commitment allowlist `{C_0,C_1}`.
- **Stage 1 — the JOIN-AIR (verifier-AIR):** one fixed-point circuit that
  verifies TWO child proofs of its own canonical shape in-circuit (replay the
  Poseidon2-M31 transcript, check the 38-query FRI fold + Merkle decommits,
  re-evaluate the inner OODS composition, enforce commitment ∈ `{C_0,C_1}`,
  check the seam `child_L.right_boundary == child_R.left_boundary` over the
  bound `SegmentState` fields), and EXPOSE left/right boundary `SegmentState`s
  as its own public inputs.
- **Stage 2 — binary tree:** 75 join nodes, depth ⌈log2 76⌉=7, level-0 = 38
  independent leaf joins (fully parallel offline). A thin LIFT-AIR normalizes a
  raw segment proof into join shape at the leaves if the two shapes differ.
- **Stage 3 — settlement verify:** the aggregate proof (one canonical Circle-
  STARK) is verified by a javm-free, prover-feature-free, Poseidon2-M31
  verify-only stwo crate in a JAM REFINE service (PVM); Substrate wasm32 pallet
  fallback.

## Topology: BINARY TREE (not single-layer, not IVC)

- All 76 inputs share ONE canonical shape ⇒ the join-AIR is one fixed circuit and
  the uniform-recursion fixed point is achievable.
- Per-node cost is CONSTANT (verify 2 fixed-shape children + a ~120-byte seam) ⇒
  the final root proof is one canonical STARK, constant-size regardless of N.
- Critical path = 7 join-proves (the rest parallel). Proving is offline.
- REJECT single-layer N-to-1: the final proof's log_size balloons (~+7) → not
  constant-size, and needs all 227 MiB resident. REJECT linear-IVC as primary:
  depth-76 sequential + subtler accumulator soundness; keep as fallback (same
  O(1) output, same public inputs).

## Aggregate public inputs (so verify_aggregate ≡ verify_chain + io-binding)

- `expected_initial_root` — `root.left_boundary.memory_root == expected_initial_root`.
- `final_memory_root` — `root.right_boundary.memory_root`.
- `io_hash` — IS `root.right_boundary.registers[9..13]` (the io-hash is a
  register sub-window of the final `SegmentState`, so it threads up the tree for
  free; `proof.rs:210-216`).
- `program_commitment_allowlist {C_0,C_1}` (or its hash) — every leaf's segment
  commitment proven ∈ this set in-circuit.
- IMPLICITLY BOUND: per-segment STARK validity (every leaf verified in-AIR) +
  full continuity (every interior seam checked once at the join spanning it;
  equality transitivity leaves only leftmost-initial / rightmost-final at the
  root). `N` never appears — the proof is constant-size and N-free.

## The verifier-AIR is HASH-DOMINATED (cost model)

Per inner-proof verify ≈ **~16,000 Poseidon2-M31 permutations** (~99.5% of the
trace), only ~56K field muls (<1%):

- FRI-layer Merkle paths ≈ **8,664 hash_children** (19 layers × 38 queries) — the
  single dominant term.
- Trace-tree decommit ≈ 3,192 hash_children + ~3,040 leaf perms (4 trees, height ~21).
- Transcript replay ≈ 397 perms.
- Field arithmetic: FRI fold ~2.2K QM31 muls, DEEP/OODS quotient ~46K, inner-AIR
  re-eval ~8K.

A join node verifies 2 children ≈ 32K perms; ×75 ≈ 2.4M perms total, but the
critical path is 7 sequential join-proves. Final proof target ~1–2 MiB (vs 227 MiB
chain today). **The gating unmeasured number is the join-AIR's natural log_size**
— it must stay ≤ the canonical ~19 for the fixed point to hold.

Two structural facts that pin the design:
1. The stwo verifier RE-EVALUATES the full 31-component inner AIR at the OODS
   point (`verifier.rs:111-120`), so the verifier-AIR MUST embed every inner-AIR
   constraint (~530 source `add_constraint` sites). Cannot be replaced by
   "check a committed composition value".
2. The **W0 commitment-allowlist is load-bearing**: production verify illegitimately
   re-runs prover-side preprocessed-trace generation (`verify.rs:376-380`), which
   is NOT arithmetizable. The allowlist replaces it with a cheap commitment∈{C_0,C_1}
   membership check. *Without the allowlist, native recursion is infeasible* — W0
   was a recursion prerequisite, not throwaway.

## Verifier-AIR chips (new) + reuse map

| Chip | Reuses | New work |
|---|---|---|
| **Poseidon2PermChip** (width-16, the shared workhorse, ~16K invocations) | spike permutation + stwo poseidon constraint template; chip anatomy from `memory_merkle.rs`; Range256 lookups | **Flatten x^5 (deg 5) → 3 deg-2 steps + helper cols** (blake2b idiom) — every zkpvm chip is degree ≤ 2; vetted width-16 M31 constants (spike uses placeholder 1234) |
| **MerkleDecommitChip** (verify one opening path vs root) | **HIGHEST LEVERAGE: `memory_merkle.rs` already verifies Merkle paths in-AIR** — keep the logup schedule, level range-check, parent/child relation | drop the dual before/after pass (halves cols); swap blake2b→Poseidon2 hash_children; generalize to FRI bit-reversed packed-leaf layout + re-derive index-soundness |
| **ChannelChip** (Poseidon2 sponge, full Fiat-Shamir replay) | drives Poseidon2PermChip; CONSUMES one perm per absorb/squeeze (like `memory_merkle` consumes blake2b); PRODUCES challenges via `register_relation!` | build the M31-algebraic transcript itself; arithmetize `verify_pow_nonce` as a small bit-decomp |
| **FriFoldChip** (QM31 ibutterfly + alpha-fold per query/layer) | EvalAtRow extension-field (QM31) machinery; witnessed-inverse from CpuChip Phi7 | **NEW idiom — no chip constrains explicit QM31 ops yet**; build a shared QM31-as-4×M31 helper module (witnessed mul/inverse) + unit-test first |
| **OodsCompositionChip** (re-eval inner 31-component AIR at OODS) | the QM31 helper module; `BASE_COMPONENTS` as spec | embed all 31 inner components' constraints (~530 sites → few-thousand terms); 2nd structural cost after hashing |
| **ChainGlueChip** (allowlist membership, seam, anchor, io-hash) | byte-eq idioms from `memory_root_boundary.rs`, `register_memory_boundary.rs` | compare only the BOUND `SegmentState` fields (pc/ts/registers[13]/memory_root), NOT the vestigial `memory_commitment` |

## Where the verify runs + buildability

- **PRIMARY: JAM REFINE stage (PVM).** Refine is the workhorse for stateless
  proof-verification (~6s PVM gas, ~15 MB work-item/slot — confirm the exact
  graypaper constant); accumulate records only the settled root + bank-deltas.
- **Buildability: BUILDABLE as a SEPARATE crate.** The current "can't build for
  PVM" blocker is feature-unification, not verify math: zero blst/bls in
  stwo/verifier source — blst leaks only transitively via javm. The aggregate
  verifier carries NO PVM-opcode semantics (its AIR is FRI/Merkle/OODS, not
  voucher-check), so it DROPS javm entirely (kills blst), uses verify-only stwo
  with prover+parallel OFF (kills blake3+rayon) + the Poseidon2-M31 channel.
  Must be a separate crate/workspace that never co-resolves with javm/prover-stwo
  for the PVM target (Cargo feature unification is per-workspace-per-target).
  NOT yet demonstrated → a thin wasm32/PVM build spike is a P4 gate.
- **FALLBACK: Substrate wasm32 pallet** (same no_std verifier, as an extrinsic).

## Phased build plan (each phase has a de-risk gate)

> **Progress (2026-06-17):** PCS-foundation gates GREEN (`poseidon2_pcs_spike`,
> `poseidon2_chip_degree2` = P2, `poseidon2_m31_channel` = P1). **P3 underway:**
> QM31-in-AIR idiom GREEN (`qm31_constraints`); the **cross-chip logup keystone
> GREEN** (`cross_chip_logup.rs` + shared `tests/recursion_common/mod.rs`,
> commit b7b5112) — a perm PRODUCER + a compression CONSUMER prove+verify
> together through the lifted protocol on CpuBackend with the Poseidon2-M31
> channel; the **MerkleDecommit chip AIR validated** (`merkle_decommit.rs`,
> commit c209b31): AIR satisfied + each component proves alone through the
> lifted protocol. **BLOCKER RE-CHARACTERIZED + UN-BLOCKED**
> (`merkle_decommit_merged.rs`): the earlier "multi-component multi-fraction"
> theory was wrong (that combination passes generally). The real trigger is the
> custom **Poseidon2-M31 lifted stack** rejecting a SINGLE component that mixes
> the perm with constraints referencing the perm's I/O when the proof has **no
> interaction tree** (Blake2s accepts the identical AIR → not a degree/soundness
> defect; perm-only and perm+920-free-bool pass without a tree → not width/count;
> distinct round constants don't change it). Adding an interaction (logup) tree is
> the enabler. UN-BLOCK (GREEN + sound, tampered path rejected):
> `merged_decommit_logup_gate` re-hashes a Merkle path leaf→root in ONE uniform
> component (perm inline) + an interaction tree. Build the rest of the verifier-AIR
> the same way (one uniform component, NOT producer/consumer — multi-component has
> a separate residual custom-stack failure). Remaining within P1: vetted width-16
> M31 round constants (+ known-answer check). **Next within P3:** Channel/FriFold/
> Oods chips into the one-uniform-component verifier-AIR → integrate → measure
> log_size (the make-or-break).

- **P1 — Poseidon2-M31 transcript + vetted constants.** Replace the spike's
  Blake2sM31 transcript with a full Poseidon2-M31 sponge using vetted (not 1234)
  width-16 M31 round constants. **Gate:** a toy AIR proves+verifies with NO
  Blake2s anywhere on commit/transcript; constants pass a published-vector check.
- **P2 — degree-2 (flattened Poseidon2) through the LIFTED protocol at blowup 4.**
  The spike was degree-1; the stwo poseidon degree≥2 test is `#[ignore]`'d.
  **Gate:** a flattened `Poseidon2PermChip` proves+verifies through the lifted
  protocol at `LOG_CONSTRAINT_DEGREE_BOUND=1`. (If it fails, the whole degree
  budget is wrong — find out before authoring more chips.)
- **P3 — QM31 helper module + ONE in-AIR segment verifier (single-layer de-risk).**
  Build Poseidon2Perm + MerkleDecommit + Channel + FriFold + OodsComposition into
  a verifier-AIR that verifies ONE canonical Poseidon2-M31 segment proof in-AIR.
  **Gate:** it produces a valid proof AND its natural **log_size ≤ canonical ~19**
  (fixed point reachable). >19 ⇒ need a bigger canonical shape or a compression
  layer (decision point; gates the whole approach). *This is the make-or-break.*
- **P4 — fixed-point JOIN-AIR + buildability spike.** Verify TWO children + the
  seam + allowlist; make the join-AIR's OWN proof land at a re-verifiable canonical
  shape (the self-referential fixed point). In parallel: thin wasm32/PVM build of
  verify-only-stwo + Poseidon2-M31 channel. **Gate:** join verifies join-shaped
  children AND its output re-verifies (decide lift-wrapper vs single-uniform-AIR);
  verify-only-stwo compiles for wasm32 AND PVM with no blst/rayon.
- **P5 — tree driver + re-prove the 76 real segments + re-pin allowlist.**
  Offline scheduler (level-0 = 38 parallel leaf joins); re-prove all 76 segments
  under Poseidon2-M31 (recompute `{C_0,C_1}`); fold to one aggregate; wire
  `verify_aggregate`. **Gate:** 76 real segments → one aggregate; `verify_aggregate`
  ≡ today's `verify_chain_standalone_allowlist` + io-binding; federation e2e green.
- **P6 — JAM/Substrate settlement verify + gas/size profile.** Host the verifier
  in a JAM refine service (PVM) + Substrate wasm fallback. **Gate:** aggregate ≤
  work-item ceiling (~1–2 MiB) AND in-PVM verify within the 6s refine gas.

## Biggest unknowns (front-loaded into the gates)

1. **The fixed point** (P3/P4): does the join-AIR's own proof land at a
   re-verifiable canonical log_size, or does the in-AIR FRI verifier inflate it
   past ~19? The PCS spike does NOT cover this.
2. **Degree-2 through the lifted protocol** (P2): unverified at blowup 4.
3. **In-AIR FRI verification trace size** (P3): ~16K perms as constraints —
   biggest cost+feasibility unknown, completely unmeasured.
4. **QM31 arithmetic in `add_constraints`** (P3): unexercised in this codebase.
5. **In-PVM verify gas** of the aggregate vs the 6s refine budget (P6).
6. **Exact JAM byte ceilings** (graypaper appendix; spec in flux) — Substrate
   fallback de-risks this.

## Decisions for the user

- **Tree vs IVC:** recommend TREE. IVC fallback only if lift+scheduler proves too costly.
- **Lift wrapper:** single uniform join-AIR if one `component_mask` verifies both
  segment + join shapes, else a RISC-Zero-style lift-AIR. Defer to P4.
- **Allowlist binding:** recommend the **public-input-hash** form (JAM re-checks),
  so the allowlist is changeable without a new aggregate circuit.
- **Re-proving cost:** switching to a Poseidon2-M31 transcript REQUIRES re-proving
  all 76 inner segments + recomputing `{C_0,C_1}` (invalidates the baked Blake2s
  commitments). Unavoidable for native recursion — confirm the one-time cost.
- **Verify venue:** JAM refine service (PVM) per roadmap; Substrate wasm pallet
  fallback. Both from the same no_std verifier.
- **Separate crate/workspace** for the settlement verifier (prevent blst/rayon
  re-leak). Confirm willingness to restructure the dependency graph.
- **Security:** `n_queries=38` is at the 96-bit floor; can't lower to shrink the
  in-AIR FRI cost without dropping security. Confirm 96-bit is the target.
