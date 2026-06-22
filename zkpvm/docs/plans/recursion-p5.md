# P5 build plan: data-scaling the proven recursion to the real 76-segment chain

Status: **P5.0 + P5.1 + P5.2a LANDED 2026-06-18; P5.2 (OODS embed) COMPLETE
2026-06-19 (LOCAL); P5.3–P5.5 + P5-perf PLANNED.** (P5.2 = the auto-witnessing
OODS evaluator [P5.2a] driving ALL 31 components, matched vs stwo, single-
uniform-component continuous Horner proving at degree ≤ 2, total width 160720 M31
measured, AND matched against a REAL `prove_canonical` segment's
`composition_oods_eval` [P5.2b 1-3] — the OODS-embed gate is CLOSED. The
claimed-sum balance is separate and moves to P5.3's latched-challenge assembly.
See the P5.2 section's status block.)
Branch `voucher-state-transition`. P4 is COMPLETE —
the recursion *machinery* is proven (`recursion-p4.md`): the single-uniform-component
join with latched-challenge cross-chip propagation verifies a real child (P4.1) and,
as the fixed-point NODE, verifies two children of its own shape + seam + allowlist +
aggregate public inputs (P4.2). **P5 scales the DATA**: take that proven machinery
and run it on the REAL 76-segment conservation chain — re-prove the segments under
Poseidon2-M31, scale the join's per-child verify *depth* to the full 31-component
inner AIR, drive the offline tree, and wire `verify_aggregate`.

This doc is **split into self-contained sessions**. Each session block has: GOAL,
PREREQS, the concrete BUILD STEPS (with `file:line` anchors from the 2026-06-18
grounding sweep), the GREEN GATE, GOTCHAS, COST, and a START-HERE pointer. Read
`recursion-design.md` (architecture) + `recursion-p4.md` (the proven machinery) first.

---

## The three pillars → six sessions

| Pillar | Sessions |
|---|---|
| **Stage-0 — re-prove under Poseidon2-M31** | P5.0 (PCS swap), P5.1 (re-pin `{C_0,C_1}` + verify_chain) |
| **Scale per-child verify DEPTH (31 components)** | P5.2 (OODS-embed harness), P5.3 (real 31-comp child end-to-end), P5.4 (real 2-child join) |
| **Tree + settlement contract** | P5.5 (tree driver + `verify_aggregate`) |
| *(parallel perf track, optional)* | P5-perf (SimdBackend Poseidon2-M31 commit op) |

**Dependency graph:** P5.0 → P5.1 (allowlist needs the new hash). P5.0 → P5.2 → P5.3
→ P5.4 → P5.5 (the depth chain needs Poseidon2-M31 segments). P5-perf is independent
and can run any time after P5.0 (it only speeds proving, doesn't change correctness).

```
P5.0 ──┬─► P5.1 ───────────────────────────────────┐
       └─► P5.2 ─► P5.3 ─► P5.4 ─► P5.5 ◄───────────┘
P5-perf (independent, after P5.0)
```

---

## Two decisions to make BEFORE P5.0 (they shape everything)

### D1 — Backend for the re-proved segments: CpuBackend (now) vs SimdBackend (perf)
**THE gating fact (grounding §stage0.5a):** production segment proving runs on
**`SimdBackend`** (`prove.rs:13,760,769,928`), but the working Poseidon2-M31 hasher
implements the per-hasher commitment ops **only on `CpuBackend`**
(`impl BackendForChannel<P2MerkleChannel> for CpuBackend`, `recursion_common/mod.rs:412`;
there is NO `SimdBackend` `MerkleOpsLifted` for the custom width-16 M31 permutation).
So Stage-0 must EITHER:
- **(A) retarget segment proving to CpuBackend** — touches every `SimdBackend` mention
  in `prove.rs`/`verify.rs`/`erased.rs`/`framework_access.rs`; the scalar hasher makes
  proving slow (the recursion stack is ~99.5% perms; canonical-scale ≈ minutes/segment),
  but it is CORRECT and unblocks everything. **RECOMMENDED for P5 v1.**
- **(B) write a SimdBackend Poseidon2-M31 commitment op** in the stwo fork (port the
  scalar `permute`/`hash_children_m31` to packed-M31 lanes + wire `BackendForChannel`) —
  fork-level backend engineering, the single biggest perf lever, NOT on any tracked
  path. **This is P5-perf**, deferrable.

Recommendation: **(A) now, (B) as the parallel P5-perf track.** Get correctness end to
end on CpuBackend; the offline tree (P5.5) tolerates minutes/segment; swap in the SIMD
commit later if fleet throughput demands it.

**⚠ D1-A IS BIGGER THAN A TYPE SWAP (sharpened 2026-06-18).** `prove::<B, MC>` requires
BOTH the commitment scheme AND every component to be on `B`, and `B: BackendForChannel<MC>`
forces `B = CpuBackend` for `MC = P2MerkleChannel`. But the zkpvm framework's prover ABI is
SimdBackend-HARDWIRED: `MachineProverComponent` returns `Box<dyn ComponentProver<SimdBackend>>`
(`erased.rs:121,304`), the trace evals are `CircleEvaluation<SimdBackend,…>` (`erased.rs:72,202,287`),
and the prove call is `prove::<SimdBackend, Blake2sMerkleChannel>` over
`Vec<Box<dyn ComponentProver<SimdBackend>>>` (`prove.rs:911,928`). Worse, the recursion work
found `BuiltInComponent`'s interaction-trace generation is itself SimdBackend-specific. So
D1-A needs ONE of:
- **(A1) make the framework generic over `B`** — `erased.rs` returns `ComponentProver<B>`, the
  chip provers support CpuBackend. HEAVY (the SimdBackend interaction-trace-gen must gain a
  CpuBackend path).
- **(A2) `to_cpu`-transplant + raw-component rewrap** — keep SimdBackend trace+interaction
  generation (the framework as-is), `.to_cpu()` every committed eval (the proven
  `recursion_common:543-551` pattern), then drive the prove via raw stwo
  `FrameworkComponent`s on CpuBackend (NOT the SimdBackend `BuiltInComponent` provers). The
  obstruction: `prove` needs each component's `evaluate_constraint_quotients_on_domain` on
  CpuBackend, so each chip's constraints must be reachable as a CpuBackend `FrameworkEval`.
  LIGHTER if the chip `evaluate`s are already backend-agnostic (they are — generic over
  `E: EvalAtRow`), but needs a CpuBackend component wrapper.
- **(A3 = B) the SIMD Poseidon2-M31 commit op** — collapses D1 and P5-perf: if the commitment
  rides SimdBackend, NOTHING in the framework changes (stay `prove::<SimdBackend, P2MerkleChannel>`).
  This may actually be the CLEANEST path despite being "perf" work, because it avoids the
  framework-backend surgery entirely.

**Implication:** the very first P5.0 step is a backend-mechanism SPIKE (A1 vs A2 vs A3),
not the alias threading. Budget P5.0 as **1 spike + 1 plumbing session**, or fold the spike
into a longer P5.0. The A3 option means P5-perf might be a PREREQUISITE, not a parallel track —
resolve this in the spike before committing to A.

### D2 — Vetted round constants: land BEFORE re-baking `{C_0,C_1}`
`recursion_common/mod.rs:61-64` uses **placeholder `1234`** round constants ("vetted
width-16 M31 constants are a documented P1 follow-up", `mod.rs:26`). The placeholder
proves+verifies (plumbing is constant-independent) but is **cryptographically a
placeholder**. The baked `{C_0,C_1}` commitments are a FUNCTION of the constants, so
re-baking them (P5.1) must happen AFTER the real constants land — else they get
re-baked twice. **Therefore: vetted constants are a P5.0 sub-task (or a thin session
between P5.0 and P5.1), NOT deferred past the re-bake.** Source vetted width-16 M31
Poseidon2 constants (eprint 2023/323 §5 / a published vector) + a constants-vector test.

---

## Session P5.0 — Stage-0: swap the segment PCS to Poseidon2-M31

> **DONE 2026-06-18 (voucher-state-transition, LOCAL).** All three gates GREEN.
> - **D1 backend SPIKE → mechanism = A2** (the lightest path won; no A1/A3 needed):
>   the framework generates main/preprocessed/logup-interaction traces on
>   `SimdBackend` UNCHANGED; the committed columns are `to_cpu`-transplanted to
>   `CpuBackend` at the commit boundary (`recursion_pcs::for_commit`), and the
>   proof rides `prove::<CpuBackend, P2MerkleChannel>` over `FrameworkComponent`s
>   rewrapped as `ComponentProver<CpuBackend>` (the `to_component_prover` return
>   type flips to the `ProverBackend` alias). The two object-safe ABI methods
>   (`draw_lookup_elements` channel, `to_component_prover` backend) take alias
>   types — one concrete channel/backend per build, no generics, dyn-dispatch
>   intact. GATE: ONE real 31-component canonical segment (`prove_canonical`)
>   proves+verifies under the FULL Poseidon2-M31 stack (commit AND Fiat-Shamir),
>   `program_commitment_of_proof` returns a `P2Hash`, tampered commitment
>   rejected — `zkpvm/verifier/tests/poseidon2_canonical_segment.rs` (release:
>   prove+verify+tamper 30s; debug ~12min — the scalar hasher, as predicted).
>   `cargo tree -i blake2` is CONFOUNDED (stwo always compiles its Blake2s hasher;
>   javm pulls blake2 for the PVM interpreter) — the "no Blake2s on commit/
>   transcript" property holds BY CONSTRUCTION instead (source grep: zero
>   `Blake2s*` symbols on the PCS path under the feature; only the
>   `#[cfg(not(poseidon2-channel))]` production aliases name them).
> - **D2 constants → Grain LFSR**: baked vetted width-16 M31 constants
>   (`src/poseidon2/mod.rs`), generated by the canonical Grain LFSR (daira/
>   pasta-hadeshash + HorizenLabs/poseidon2 Poseidon2 layout: `(R_F·t)+R_P=142`
>   elements, 4 begin-full×16 → 14 internal×1 → 4 end-full×16). Constants-vector
>   test re-derives + pins them (`tests/poseidon2_round_constants.rs`, 3/3 green).
> - **Plumbing**: new `src/poseidon2/` + `src/recursion_pcs.rs` (alias module,
>   single `cfg` point) + feature `poseidon2-channel` (zkpvm + zkpvm-verifier);
>   threaded prove.rs/verify.rs/proof.rs (v8→v9, feature-gated)/program_id.rs/
>   erased.rs/framework_access.rs/verifier-crate. All 4 build configs compile
>   (prover/verify × default/feature).
> - **OPEN (P5.2 prereq, NOT P5.0/P5.1):** `tests/recursion_common/mod.rs` still
>   carries its OWN copy of the permutation with PLACEHOLDER `1234` constants — it
>   has now DRIFTED from `src/poseidon2`'s Grain constants. The 18 recursion
>   chip-tests are constant-independent so still pass, and P5.1 re-bakes via
>   `prove_canonical` (= `src/poseidon2`, unaffected). But P5.2's verify-AIR
>   replays the REAL prover transcript, so its FIRST step must align
>   `recursion_common` to re-export `zkpvm::poseidon2` (constants + `permute` +
>   hasher), keeping only the recorder channel / `eval_permutation` /
>   `record_permutation` / relation / `to_cpu` / configs local.

**GOAL.** Re-prove a single conservation segment under a Poseidon2-M31 Merkle channel +
Fiat-Shamir transcript (no Blake2s on commit/transcript), with the program commitment a
`P2Hash`. This is "Phase C1" from `trustless-chain-verification-roadmap.md:102-116`, now
UNBLOCKED because we built the M31-Poseidon2 hash (the roadmap's external gate is gone).

**PREREQS.** P4 done. Decisions D1 (backend) + D2 (constants).

**BUILD STEPS.**
1. **Promote the hasher into a lib module.** `P2MerkleHasher`/`P2MerkleChannel`/
   `Poseidon2M31Channel`/`permute`/`hash_children_m31`/`record_permutation`/`mobile_config`
   currently live in the test-only `zkpvm/tests/recursion_common/mod.rs`. Move them into a
   real module (e.g. `zkpvm/src/poseidon2/` or a small `zkpvm-hash` crate) so `prove.rs`/
   `verify.rs`/`program_id.rs`/the verifier crate can use them. Swap the placeholder round
   constants for vetted ones (D2).
2. **Feature-gate the channel/hasher aliases.** Add (behind `--features poseidon2-channel`):
   ```
   type ProverChannel        = Poseidon2M31Channel;   // was Blake2sChannel
   type ProverMerkleChannel  = P2MerkleChannel;        // was Blake2sMerkleChannel
   type ProverMerkleHasher   = P2MerkleHasher;         // was Blake2sMerkleHasher
   type ProverBackend        = CpuBackend;             // was SimdBackend  (D1-A)
   ```
   Thread them through the swap surface (grounding §stage0.6 — all hardcoded today):
   - `prove.rs`: channel `:766`, `CommitmentSchemeProver::<_, _>` `:768-769`,
     `stwo::prover::prove::<_, _>` `:928`, imports `:4,:9,:13`, backend `:760,883,911`.
   - `verify.rs`: channel `:228`, scheme `:243`, verify `:344`, `verify_preprocessed_trace`
     signature `:347-350`, scheme `:374`, imports `:5,:9`.
   - `proof.rs`: `Proof.stark_proof: StarkProof<ProverMerkleHasher>` `:150`, import `:10`;
     **bump `PROOF_FORMAT_VERSION` (`:122`, currently 8 → 9).**
   - `framework/traits/erased.rs`: `draw_lookup_elements(channel: &mut ProverChannel)`
     `:46-50` + prover mirror `:167`; `SimdBackend` returns `:72,111,121,133,202,287` (if D1-A).
   - `framework_access.rs`: `draw_all_lookup_elements(…, channel: &mut ProverChannel, …)`
     `:32-34`, import `:9`.
   - `program_id.rs`: `ProgramCommitment = P2Hash` `:39`; `program_commitment_of_proof`
     reads `commitments[0]` `:53-55` (now a `P2Hash`).
   - `verifier/src/lib.rs`: `CommitmentHash = P2Hash` `:45`, channel `:220`, scheme `:233`,
     verify `:340`; all `verify_standalone*`/`verify_chain_standalone*` signatures
     (`:70,92,109,118,382,404,477`).
   - `examples/extensions/prover/src/lib.rs`: `CommitmentHash`/allowlist types `:65,479`
     flip with the verifier (the prove/verify *functions* are channel-agnostic).
   - **THE OBSTRUCTION (grounding §stage0.6):** `draw_lookup_elements`/`draw_all_lookup_elements`
     are *object-safe trait methods* taking a concrete `&mut Blake2sChannel`. Making them
     generic over `C: Channel` breaks dyn-dispatch. CHEAPEST fix = a per-build `type
     ProverChannel = …` alias toggled by the feature (one concrete channel per build), NOT a
     generic. (Per-channel vtable monomorphization is the heavy alternative.)

**GREEN GATE.** One conservation segment (the `prove_canonical` path, `prove.rs:572`)
proves+verifies under Poseidon2-M31: `cargo test --features poseidon2-channel` — segment
round-trips, `program_commitment_of_proof` returns a `P2Hash`, `cargo tree -i blake2`
shows no Blake2s on the commit/transcript path. A `debug-internals` AssertEvaluator pass
on the real 31-component trace stays green.

**GOTCHAS.** The `StarkProof<H>`/`ProgramCommitment`/`CommitmentHash` types are in
SERIALIZED/ABI positions (`proof.rs:150`, `program_id.rs:39`, `verifier:45`) — the wire
format changes, hence the version bump. `P2Hash` is `Serialize/Deserialize`
(`recursion_common/mod.rs:172`) so it serializes fine. The scalar hasher (D1-A) makes the
real-31-component segment prove slow — budget minutes, not the sub-second Blake2s mobile
prove. `cargo clean -p stwo` on inexplicable `ConstraintsNotSatisfied` (stale-rlib gotcha).

**COST.** **1 backend-mechanism spike (D1: A1/A2/A3) + 1 wide plumbing session.** The
alias threading is mechanical but wide (~9 files + lib promotion + constants); the spike
that precedes it (which backend mechanism — see D1's sharpened note) is the real unknown and
must come first. The prove-time regression (if A1/A2) is expected and acceptable (offline).

**START HERE.** **The D1 backend spike FIRST** — prove ONE real 31-component segment under
`P2MerkleChannel`, trying A2 (`to_cpu`-transplant the SimdBackend-generated trace + a
CpuBackend `FrameworkComponent` rewrap) as the lightest plausible path; if the per-chip
CpuBackend wrapper is intractable, fall back to A3 (the SIMD commit op) or A1 (framework
genericization). Read side by side: `prove.rs:674-928`
(`prove_impl_with_components_overridden`, the SimdBackend prove path), `erased.rs:121,304`
(the SimdBackend component-prover ABI), `recursion_common:543-551` (the `to_cpu` transplant),
and `poseidon2_pcs_spike.rs:370-413` (the working `prove::<CpuBackend, P2MerkleChannel>` round
trip). Only after the backend mechanism is chosen does the alias threading begin.

---

## Session P5.1 — re-pin `{C_0,C_1}` + verify_chain under Poseidon2-M31

> **MOSTLY DONE 2026-06-18 (voucher-state-transition, LOCAL).** `{C_0,C_1}` re-pinned
> under Poseidon2-M31 + `verify_chain_standalone_allowlist` GREEN.
> - **P2Hash ↔ 32-byte ABI:** `P2Hash::{from(&[u8]), to_bytes()}` (8 LE-`u32` limbs,
>   reduced mod p) + a channel-agnostic `recursion_pcs::commitment_bytes(&hash)`
>   bridge (Blake2s → `.0`; P2 → `to_bytes`). The prover-extension lib + the
>   re-bake recipe / drift guard now use the bridge instead of `.0`, so they
>   compile + run under BOTH stacks. `poseidon2-channel` forwarded to
>   `prover-extension` (→ zkpvm + zkpvm-verifier).
> - **Re-pinned `{C_0,C_1}`** (feature-gated `VOUCHER_CHECK_COMMITMENTS` —
>   default keeps the Blake2s values; the P2 const is a SEPARATE `#[cfg]` arm):
>   `canonical_commitment_allowlist` under `--features poseidon2-channel`
>   (SEG_STEPS=100000, ~34 min, release) re-derived them as `P2Hash` LE bytes:
>   `C_0 = c8ebc64c73b600790984c72c87c2e0502750510f2d46cf5fa6afe71bc5cfdb7a`
>   (comb-free; seg 0 AND seg 75 unify), `C_1 = 5b1cdb6ec0409e2221859f4916ef76381fa41d1e8cf9e43f51abe80c26925538`
>   (comb seg #57 of 76). W0 GATE GREEN — the 2-entry allowlist + the
>   C_0–C_1–C_0 heterogeneous chain verify under P2. The CANONICAL PROFILE is
>   UNCHANGED (hash swap doesn't move log_sizes — trace-gen is identical).
> - **DRIFT GUARD:** `canonical_commitment_drift_guard` under the feature
>   re-derives + asserts the baked `{C_0,C_1}` (confirms the bake).
> - **CAPSTONE DEFERRED to P5-perf:** `chain_manifest_roundtrip` proves the FULL
>   76-segment chain (`prove_chain_segments`) — at ~34 min for the 6-segment
>   recipe, that is ~7 h under the scalar Poseidon2 hasher, impractical until the
>   SIMD commit op (P5-perf) lands. The federation `verify_chain_segments` LOGIC
>   (allowlist lookup, io-binding, guards) is channel-independent: the io-binding
>   is a register-bytes hash check (not the PCS), and the guards are covered by
>   `manifest_codec_and_verify_guards`. `verify_chain_standalone_allowlist` itself
>   is already GREEN under P2 via the recipe's real C_0–C_1–C_0 chain.

**GOAL.** Recompute the 2-entry canonical allowlist under the new hash, re-bake the const,
and get `verify_chain_standalone_allowlist` + the federation chain e2e green under
Poseidon2-M31.

**PREREQS.** P5.0 (segments prove under Poseidon2-M31). Vetted constants (D2) landed.

**BUILD STEPS.**
1. **Recompute `{C_0,C_1}`.** The mechanism already exists: `canonical_commitment_allowlist`
   (`examples/extensions/prover/tests/prove_transition.rs:847-995`) traces the transition,
   segments at `SEG_STEPS=100_000`, `prove_canonical`s two comb-free segments + the one comb
   segment, reads `program_commitment_of_proof` (= `commitments[0]`, now `P2Hash`), asserts
   the two comb-free roots collapse to one `C_0` and the comb segment yields a distinct `C_1`,
   and PRINTS the new 32-byte arrays (`:991-994`).
2. **Re-bake.** Paste the new `C_0`/`C_1` into `VOUCHER_CHECK_COMMITMENTS`
   (`examples/extensions/prover/src/lib.rs:504-519`); `canonical_commitment_drift_guard`
   (`prove_transition.rs:1008`) re-validates. Re-measure `VOUCHER_CHECK_CANONICAL_PROFILE`
   (`prover:488-490`) only if the AIR shape changed (it shouldn't — hash swap alone).
3. **Federation types flip** with the verifier crate (`allowlist_for_commitment`
   `prover/src/lib.rs:391,449-458`; `verify_chain_segments` `:380-432`).

**GREEN GATE.** `canonical_commitment_drift_guard` passes (re-derived `{C_0,C_1}` == baked,
under Poseidon2-M31). `verify_chain_standalone_allowlist` (`verifier/src/lib.rs:477-525`)
green on a real multi-segment chain. The federation capstone (`prove_transition.rs:1128`,
`prove_chain_segments` → `verify_chain_segments`) round-trips under the new hash. The
io-binding (final-segment `public_io_hash() == compute_io_hash`, `prover:404-409`) still holds.

**GOTCHAS.** The baked Blake2s commitments go STALE the instant the hash flips — every LIVE
chain rejects (`allowlist_for_commitment` returns `None`) until re-baked. This is a
one-time, mandatory re-bake (the const is the single pinned point). Format version already
bumped in P5.0.

**COST.** ~0.5–1 session (mostly running the re-bake test + pasting + e2e).

**START HERE.** `verifier/src/lib.rs:477-525` (`verify_chain_standalone_allowlist`) +
`prove_transition.rs:847-995` (`canonical_commitment_allowlist`, the re-bake recipe).

---

## Session P5.2 — the 31-component OODS-embed harness (THE hard one)

> **PREREQ DONE 2026-06-18 (commit `6d0cd77`, LOCAL):** `recursion_common`
> re-exports the prover's vetted Grain constants from `zkpvm::poseidon2` (was
> placeholder `1234`), so the verify-AIR's `eval_permutation` / `record_permutation`
> match the segment prover's committed transcript. Validated: the constant-sensitive
> recursion gates (channel_chip transcript-replay, cross_chip_logup, fri_twiddle_chip,
> qm31_constraints) pass with the real constants.
>
> **P5.2a DONE 2026-06-18 (commits `e620bd4` / `26d4f8f` / `064e64b`, LOCAL):**
> the auto-witnessing OODS evaluator is BUILT and de-risked end-to-end. New
> `tests/recursion_common/oods_auto.rs`: `Handle<B>` (value + degree bound;
> Mul of two degree-1 handles lowers the product to a fresh witnessed column),
> `OodsEval<B>` (the chip walks it; `add_constraint` folds into a Horner
> accumulator with each `acc·rc` witnessed; full logup path replicating stwo's
> `pub(crate)` `logup_proxy!()` + a `LogupAtRow`), and a two-mode `WitBackend`
> (`RecordBackend` host V=SecureField → ordered column schedule + composition
> value; `VerifyBackend<E>` in-AIR V=E::EF → degree-2 bindings + DEEP-ALI
> equality). One walk serves both passes; layout agrees by construction.
> Gates (all GREEN):
> - **small AIR** (`tests/oods_auto_chip.rs`): driving the GATE-4 a·b/a·inv chip
>   re-derives the IDENTICAL witnessing GATE 4 hand-wrote (5 products, 32 QM31
>   cols); composition value == stwo's `eval_composition_polynomial_at_point`;
>   proves+verifies at degree ≤ 2; tamper rejected.
> - **logup** (`tests/oods_auto_logup.rs`): a chip with `add_to_relation` +
>   `finalize_logup` re-evaluated against a synthetic mask; 7 witnessed products
>   (incl. each logup `diff·denominator`); matches stwo; proves+verifies.
> - **real CpuChip** (`tests/oods_auto_cpu.rs` + crate seam
>   `framework_access::drive_cpu_chip_oods`): the heaviest chip (187
>   `add_constraint` + 45 `add_to_relation`) driven through the evaluator with NO
>   hand-port; in-AIR re-eval == stwo's `evaluate_constraint_quotients_at_point`;
>   assert_constraints green; proves+verifies (~66s); tamper rejected.
>
> **WIDTH MEASUREMENT (the P5.2b risk, previewed):** CpuChip alone embeds as
> **2329 committed QM31 columns (1529 witnessed products) = 9316 M31 trace
> columns** at degree ≤ 2 (synthetic-mask, log_size 6). This is the input to the
> full-31-component width budget and the prove-cost the design flags. The mask is
> SYNTHETIC (shape from `Component::mask_points`, random samples — the
> per-component contribution is a pure function of the mask, so this fuzzes the
> arithmetisation); the REAL-segment transcript replay + per-component mask
> slicing + claimed-sum balance is **P5.2b**.
>
> **P5.2b steps 1+2 DONE 2026-06-19 (commits `2c49bc5` / `5bb37e4`, LOCAL):**
> - **Seam generalised:** `framework_access::drive_chip_oods(chip_idx, ..)`
>   dispatches over all 31 `BASE_COMPONENTS` (the per-index match; CpuChip seam is
>   now a wrapper). The evaluator tolerates a constraint-free component (acc=0) and
>   `RecordBackend::set_preproc_indices` remaps preprocessed reads through a chip's
>   `preprocessed_column_indices` (stwo's remap — preprocessed reads aren't a
>   contiguous identity range for every chip; the preprocessed tree is sized to the
>   full column set).
> - **Step 1 — all 31 matched + width measured (`tests/oods_auto_all31.rs`):**
>   every one of the 31 chips' OODS re-eval reproduces stwo's per-component
>   `evaluate_constraint_quotients_at_point` (each chip's `evaluate` survives the
>   degree-reducing evaluator, no hand-port). **TOTAL embed ≈ 40180 QM31 = 160720
>   M31 field values** (23325 witnessed products). Heaviest = Blake2bChip (9549
>   QM31), then Blake2bBoundary (7858), Ristretto (6252); CpuChip 2318. These are
>   committable VALUES (width OR distributed across the ~16K perm rows → ~10 M31/row
>   if spread, so negligible added WIDTH — the design's width worry resolves
>   favourably modulo the P5.3 layout).
> - **Step 2 — single-uniform-component continuous Horner
>   (`tests/oods_auto_join31.rs`):** `drive_multi` walks all 31 chips through ONE
>   `OodsEval`, the Horner accumulator running continuously across them (logup reset
>   per component), reproducing the GLOBAL `PointEvaluationAccumulator` (one
>   composition value, not a sum of per-component contributions) — the exact shape
>   the join takes; `assert_constraints` green; embed 40150 QM31. **The full
>   single-uniform-component join proves+verifies at degree ≤ 2 (~23s release,
>   `#[ignore]` for the debug suite) AND rejects a tampered column — even as PURE
>   width (160600 M31 columns, no distribution across perm rows), so the design's
>   "unmeasured width" make-or-break resolves FAVOURABLY.**
>
> - **Step 3 — REAL-segment composition match DONE 2026-06-19 (commit `1c1c6d0`,
>   `tests/oods_auto_real_segment.rs`):** a real `prove_canonical` 31-component
>   segment proof's actual OODS composition is re-evaluated in-AIR and matches its
>   own `composition_oods_eval`. New crate seam
>   `verify::reconstruct_oods_for_recursion` replays the verifier's FS transcript
>   (the channel-affecting steps of `verify_with_options_explicit_components` + the
>   stwo verifier head) and returns the per-component masks sliced from
>   `sampled_values`, the drawn `lookup_elements`, the oods-derived scalars, the
>   per-component claimed_sum/log_size, and the proof's composition value
>   (= the recombined real composition mask). KEY: components are selected by the
>   PROOF's `component_mask` (canonical forces all 31), NOT
>   `active_components_verifier` (which drops naturally-inactive chips ⇒ trace-layout
>   mismatch). All 31 driven through the evaluator (continuous Horner, real mask)
>   reproduce the proof's `composition_oods_eval` (~24s release, `#[ignore]`).
>
> **⇒ THE P5.2 OODS-EMBED GATE IS CLOSED:** the full 31-component composition
> re-evaluates in-AIR at degree ≤ 2 as ONE uniform component, matches a REAL
> proof's `composition_oods_eval`, `assert_constraints` green, proves+verifies,
> width measured (160K M31, tractable).
>
> **REMAINING (→ P5.3, the per-child assembly):** the **claimed-sum balance** is
> SEPARATE from the OODS re-eval (`recursion-p5.md` BUILD STEP 3) and pairs with
> the latched-challenge assembly: `claimed_sums.sum()==0` (`verify.rs:299`, a
> degree-1 sum over committed columns) + the boundary-binding claimed sums
> (`verify.rs:316-327` → `boundary_binding::check_boundary_claimed_sums`, which
> recomputes the 4 boundary chips' sums as witnessed inverses of relation combines
> over the public boundary states — `expected_{register_file,program_boundary,
> memory_root}_sum`). The `reconstruct_oods_for_recursion` seam already returns the
> real `claimed_sums` + `lookup_elements` these need.

**GOAL.** Replace GATE 4's representative 2-constraint OODS consumer with a harness that
re-evaluates the FULL canonical segment AIR (31 components, **530 `add_constraint` sites**,
grounding §31comp.2) at the OODS point, in-AIR, degree ≤ 2. This is the verify *depth* the
join needs; it is the biggest unmeasured cost (`recursion-design.md:197-199`).

**PREREQS.** P5.0 (a real Poseidon2-M31 segment to extract OODS data from). GATE 4's
`oods_composition_chip.rs` + `join_assembly.rs` as templates.

**THE CENTRAL DESIGN QUESTION — reuse vs hand-port.** The 31 chips implement
`BuiltInComponent::add_constraints` / `FrameworkEval::evaluate` **generic over `E: EvalAtRow`**
(`framework/traits/builtin.rs:42-47`, `framework/eval.rs:45-49`). stwo's own OODS check
(`core/air/components.rs:54-71`) re-runs each component's `evaluate` against the OODS mask via
a `PointEvaluationAccumulator`. So in principle the join's OODS consumer can REUSE the real
chips' `evaluate` — feeding them a custom `EvalAtRow` that (a) returns OODS samples from the
join's committed columns for `next_trace_mask()`, and (b) accumulates each `add_constraint`
into the composition. The obstruction: the chips' constraints are arbitrary-degree, but the
join-AIR needs degree ≤ 2 with every QM31 product WITNESSED. Two options:
- **(P5.2-reuse) An auto-witnessing `EvalAtRow`.** A custom evaluator that, as it walks a
  chip's `evaluate`, allocates a join-column per intermediate QM31 product (degree-reduction
  on the fly) and emits the degree-2 witnessing constraints. Drive all 31 chips' real
  `evaluate` through it. **Highest leverage — no hand-porting of 530 sites — but the
  auto-witnessing evaluator is real new machinery.** De-risk it on ONE heavy chip first.
- **(P5.2-port) Hand-port** each chip's constraints into the `oods_composition_chip.rs`
  witnessed-product idiom. Faithful, mechanical, but 530 sites × the QM31 witnessing — large
  and error-prone.

**BUILD STEPS.**
1. **Prototype the auto-witnessing `EvalAtRow`** and drive the **CpuChip** (`chips/cpu/mod.rs`,
   193 of the 530 sites — the heaviest) through it at the OODS point, cross-checked against
   stwo's `eval_composition_polynomial_at_point` for that component. GATE: the in-AIR
   re-eval of CpuChip's constraints matches stwo's accumulator contribution.
2. **Scale to all 31** components (the full `BASE_COMPONENTS`, `lib.rs:214-246`), accumulating
   in stwo's exact order (`air/components.rs:61-70`). The OODS mask now carries one QM31 sample
   per committed column across preprocessed + main + **interaction** trees (grounding §31comp.4
   — the logup constraints over interaction columns are part of each `evaluate`, so the
   interaction-mask samples + relation constraints must be embedded too).
3. **The claimed-sum balance** is SEPARATE from the OODS re-eval (it's the ChannelChip path):
   `claimed_sums.sum() == 0` (`verify.rs:296-300`) + the boundary-binding claimed sums
   (`verify.rs:313-324`, `boundary_binding.rs:116-168`, the 4 boundary chips). Wire these as
   their own constraints driven by the latched challenges (the GATE 4 latch pattern).

**AS-GROUNDED DESIGN (the auto-witnessing evaluator, 2026-06-18 sweep).** The
mechanism is a **two-pass walk of the chip's own generic `evaluate<E: EvalAtRow>`**, the
SAME walk both times so the column layout agrees by construction (the sequential
`next_interaction_mask` cursor is the coupling). Anchors below are stwo rev e128672
(`~/.cargo/git/checkouts/stwo-59e22971a65c0edb/e128672/crates`) unless noted.
- **Ground truth to match:** `PointEvaluator` (`constraint-framework/src/point.rs:38-65`)
  IS the reference `EvalAtRow` — `F=EF=SecureField`; `next_interaction_mask` (`:42-52`) is a
  per-tree cursor (offsets ignored, one pre-sampled QM31/col); `add_constraint` (`:53-59`) is
  exactly `acc.accumulate(denom_inverse * constraint)`; `combine_ef` = `from_partial_evals`.
  The accumulator (`core/air/accumulation.rs:29`) is Horner: `acc = acc*random_coeff + eval`
  (earliest constraint → highest power); components fold in `BASE_COMPONENTS` order
  (`air/components.rs:54-71`). `denom_inverse = coset_vanishing(CanonicCoset::new(mlbd).coset,
  oods).inverse()` (`component.rs:257`); `mlbd` + `oods_point` + `random_coeff` extracted by
  the GATE-4 replay (`oods_composition_chip.rs:177-248`).
- **Entry point:** build `BuiltInComponentEval{ component:&chip, log_size, lookup_elements }`
  (`framework/eval.rs:24-49`) and call `.evaluate(my_E)`. `TraceEval::new` (`trace/eval.rs:21-45`)
  pulls EVERY mask up front (preproc via `get_preprocessed_column`, main via
  `next_interaction_mask(1,[0]|[0,1])`) BEFORE any constraint runs ⇒ clean two-phase: all mask
  reads, then a stream of `add_constraint`/`add_to_relation`.
- **The hard core = a degree-reducing symbolic `F`/`EF`.** Plain `SecureField` loses the
  expression structure needed to spot degree-2 products, so `E::F` must be an expression handle
  that tracks degree. On `Mul` of two degree-1 handles → allocate the next witness column +
  record its native value (Pass A) / read it back via `next_trace_mask` + emit
  `add_constraint(witness − a*b)` (Pass B), so every product stays the GATE-4 witnessed-idiom
  (`oods_composition_chip.rs:289-340`: `ab=a*b`, `t=rc*c0`, `p=dinv*inner`, final `p−lhs`).
  **LEVERAGE:** stwo already has a symbolic `ExprEvaluator` (the `CPU_EXPR_DUMP` path in
  `framework/traits/erased.rs:368-391`) — start from its AST + add the degree-track + product
  → witness lowering, rather than an AST from scratch.
- **Two passes:** (A) host-side recording E → ordered witness schedule (native QM31 values,
  appended AFTER the chip's committed cols) + the Horner accumulator value; (B) the join's
  `FrameworkEval::evaluate` re-walks with the in-AIR E, reads the witnesses via `next_trace_mask`
  in the SAME order, emits the deg-2 bindings + the fold, asserts `acc − composition_value`
  (ground truth from the replay). Witness columns live ONLY in the join's host-filled main
  trace — a custom E cannot allocate committed cols mid-eval (`add_intermediate` is a no-op,
  `lib.rs:133-141`).
- **CpuChip caveat (the de-risk target, `chips/cpu/mod.rs:93-118`):** 187 `add_constraint` +
  **45 `add_to_relation`** (logup, interaction tree 2) across 17 relations. To walk it the E
  MUST implement the logup path (`super::logup_proxy!()` + a `LogupAtRow` field, else
  `write_logup_frac`/`finalize_logup*` hit `unimplemented!()`, `lib.rs:162-175`); each logup
  denominator is another deg-2 witness. Many CpuChip constraints are ALREADY deg-2 (booleanity,
  gated helpers) — witness products ONLY where the chip expression exceeds degree 1, or the
  column count explodes. **De-risk the EVALUATOR first on the GATE-4 small AIR (a·b / a·inv),
  auto-generated == the manual version, BEFORE CpuChip's logup scale.**

**GREEN GATE.** The harness re-evaluates a REAL Poseidon2-M31 conservation segment's full
31-component OODS composition in-AIR and matches the proof's `composition_oods_eval`
(extracted via the GATE-4 transcript-replay pattern); `assert_constraints` green; it
proves+verifies at degree ≤ 2 as ONE uniform component. **MEASURE the added width
(columns/row) and the resulting log_size** — this is the unmeasured risk.

**GOTCHAS.** `BuiltInComponent`'s `generate_interaction_trace` is SimdBackend-hardwired
(the recursion work hit this — build on RAW stwo `FrameworkComponent`, not `BuiltInComponent`,
for the join), but the `add_constraints`/`evaluate` *constraint* path is backend-agnostic and
reusable. The interaction-trace mask + logup constraints roughly DOUBLE the mask columns.
Width (not depth) grows — log_size should hold ~14, but per-cell prove cost rises; that's the
thing to measure.

**COST.** **The biggest session — likely splits into 2** (2a: auto-witnessing evaluator +
CpuChip de-risk; 2b: scale to 31 + interaction + claimed-sums + measure). Budget generously.

**START HERE.** `oods_composition_chip.rs:177-248` (`extract_oods` — the transcript-replay
to get real OODS data; the 31-comp version extends `sampled_values[tree][col]` to all trees)
+ `framework/eval.rs:45-49` + `core/air/components.rs:54-71` (the accumulator the harness mirrors).

---

## Session P5.3 — verify ONE real 31-component child end-to-end

> **P5.3 UNDERWAY 2026-06-19 (voucher-state-transition, LOCAL). STEP-1 foundation
> landed + the cost model GROUNDED + the make-or-break re-scoped to a LAYOUT
> problem.** Commit `479afdd`.
>
> **What landed (the data-extraction foundation every consumer needs):**
> - A zero-overhead `PermKind`/`PermRecord` recorder on the LIB
>   `poseidon2::Poseidon2M31Channel` (None by default — production transcript
>   unaffected, behaviorally identical to bare `permute`). The test-module copy in
>   `recursion_common` stays (dedup is deferred cleanup); the LIB recorder is what
>   a REAL canonical (lib-typed) proof needs.
> - `verify::record_canonical_transcript(proof, side_note) -> RecursionTranscript`
>   (`#[cfg(all(prover, poseidon2-channel))]`): hands a recording channel through
>   the SAME transcript `verify` drives — the channel-affecting prefix of
>   `verify_with_options_explicit_components` then stwo `verify` (head + FRI commit
>   + PoW + query sampling + decommit) — returning every perm + `prefix_len` (perms
>   before the verifier head; the composition `random_coeff` is the first `Squeeze`
>   at-or-after it). Pairs with `reconstruct_oods_for_recursion` (OODS scalars/masks).
> - `tests/recursion_child_verify.rs` (`record_canonical_transcript_grounding`,
>   poseidon2-channel, `#[ignore]`, ~27s release): GREEN. Recorded composition
>   `random_coeff` MATCHES `reconstruct_oods_for_recursion`.
>
> **STEP 1b landed (commit `33d19e7`) — the data extraction is now COMPLETE.**
> `verify::extract_recursion_data(proof, side_note) -> RecursionData` replays
> stwo's `verify` head + `verify_values` via PUBLIC stwo calls (`Components::
> mask_points`, `FriVerifier::{commit,sample_query_positions,decommit}`,
> `fri_answers`, `prepare_preprocessed_query_positions`, `tree.verify`) on a
> recording channel, capturing EVERY transcript-derived datum the FRI / DEEP /
> Merkle consumers need: composition + DEEP `random_coeff`, OODS point, the
> per-FRI-layer **fold alphas** (by BRACKETING `FriVerifier::commit` — the
> squeezes it performs ARE the alphas), query positions (+ preprocessed remap),
> the first-layer FRI evals (`fri_answers` = DEEP quotients), and the lookup
> elements. It VALIDATES end-to-end (real per-tree Merkle decommit + real
> `FriVerifier::decommit` both succeed). The load-bearing FS-mix prefix is now a
> single shared helper (`recursion_verify_prefix`). GATE (`extract_recursion_data_
> grounding`, ~32s): the step-by-step replay reproduces the REAL stwo `verify`
> transcript EXACTLY (all 8584 perms, every kind/input/output) — no FS-mix drift —
> AND `random_coeff` matches reconstruct. Measured: **14 fold alphas** (1+13), **38
> query positions** (= n_queries, no collisions this segment), 38 `fri_answers`,
> **`lifting_log_size`=16** (FRI first-layer domain), **`max_log_degree_bound`=14**.
> The raw per-tree/per-FRI-layer decommit data (roots, `queried_values`,
> `hash_witness`, `fri_witness`, `last_layer_poly`) is read directly from
> `proof.stark_proof` using these query positions. ⇒ **the AIR-building session has
> all its inputs; the data half of NEXT items (c) is DONE.**
>
> **MEASUREMENT — the design cost model was WRONG about the transcript** (real
> 31-component canonical segment, small program, log_sizes ≤ 14):
> - **Transcript = 8584 perms** (8531 absorb / 51 squeeze / 2 pow), NOT the design's
>   estimated **~397**. The `mix_felts(sampled_values.flatten_cols())` absorb
>   (~17K OODS samples, one QM31 per committed column across the 4 trees) DOMINATES
>   — ~8500 RATE-8 absorb perms. ⇒ **the channel replay ALONE is ~log 14** (8584 →
>   16384 rows). (`recursion-design.md:81`'s "transcript ≈ 397 perms" is off ~20×.)
> - **FRI = 14 layers** (13 inner + 1 first; `inner_layers.len()` read at runtime —
>   NOT the predicted ~19, because this de-risk segment's max log_size is 14, not
>   the federation 19), `last_layer_poly` len 1 (degree-0 CONSTANT, as predicted),
>   38 queries, log_blowup 2, pow_bits 20, 4 trace trees.
> - **Projected integrated per-child scale:** channel 8584 perms + FRI-Merkle
>   decommit re-hash (~8.7K FRI-layer + ~6.2K trace-tree, design §75-83) ≈ **~23.5K
>   perms → log 15** (not the design's ~14). Still ≤ canonical 19 (~4 bits margin) ⇒
>   the fixed point holds, but the per-child log is **15, not 14**.
>
> **THE RE-SCOPED MAKE-OR-BREAK = the LAYOUT problem (the crux the design deferred
> as "modulo P5.3 layout").** P5.2 proved the 31-comp OODS embed as PURE WIDTH
> (160600 M31 cols) at log 6 (64 rows, ~23s). But the channel forces ~16384 rows,
> and replicating 160600 cols × 16384 rows ≈ 2.6 BILLION cells = OOM. So the OODS
> embed MUST DISTRIBUTE across the ~16K perm rows (~10 M31/row, per
> `recursion-design.md` and `project_recursion_build`). Distributing the embed turns
> its **sequential Horner accumulator** (`oods_auto::drive_multi`: `acc·rc + c`,
> witnessed step by step — currently single-row-replicated by `gen_join_trace`) into
> a **CROSS-ROW chain** (each row does one `acc·rc + c` step reading the previous
> row's `acc` via a `[-1,0]` mask, the channel's own latch mechanism). This is a
> redesign of `OodsEval`/the join-trace layout into a row-streaming form — the real
> P5.3 engineering, and the gate for integrating OODS with the channel/FRI/Merkle in
> ONE uniform component.
>
> **LAYOUT VIABILITY PROVEN 2026-06-19 (commit `41d6caa`,
> `tests/recursion_offset_spike.rs`).** The foundational unknown was whether a
> circle-STARK mask offset `k` reads exactly logical row `i+k` for `|k|>1` (the
> proven ChannelChip/FriFoldChip only ever use ±1; the circle domain is a coset,
> not a line, so clean composition of the group step was not obvious). Spike: fill
> one column `v[storage(i)]=i`, read it at signed offsets ±{1,2,3,8,16,24} (small
> AND up to ~N/2) in one mask, constrain `v@±k − v@0 == ±k` gated past the wraps —
> GREEN + the wrong-expectation control rejected ⇒ **every tested offset reads
> EXACTLY logical row i+k.** So the streamed evaluator CAN read operands from
> nearby rows. **DESIGN (grounded):** lay the `OodsEval` `schedule` down the rows as
> a small set of "register"/lane columns; each row computes one witnessed product
> or Horner step reading operands at FIXED small relative offsets (`{0,-1,…,-W}`,
> W = the dataflow cut-width) + LATCHED constants (rc/dinv/ox/comp_mask + the
> lookup `z`/`alpha`, held constant via the channel's `not_last` eq). To keep the
> outer OODS mask small the DISTINCT offset set must be bounded (≈W), which needs a
> scheduling pass that keeps live values within a window of W (read masks lazily —
> right before use — not all up-front as `TraceEval::new` does today). Rows ≈
> schedule length / ops-per-row (≈40150 → log 16 single-lane, fewer if banded);
> width ≈ W + latched.
>
> **STREAMED-SHAPE TRACTABILITY MEASURED 2026-06-19 (commit `1950ef9`,
> `tests/recursion_stream_scale.rs`).** A representative streamed AIR — a cross-row
> Horner whose per-row contributions are `L` WITNESSED QM31 products, accumulator
> chained across rows, matched to a host composition — at **log 14, L=3 = 49152
> witnessed products** (≈ the embed's 40150): **GREEN, ~5s/prove, 68 main M31
> cols/row, tampered column rejected.** ⇒ the streamed embed (a) **FITS in log 14**
> = the channel's own row count, so it SHARES the channel's rows and adds no depth
> (with L≈3, 40150 nodes land in ≤16384 rows); (b) is **68 cols/row** (vs 160600
> width-replicated), ~1.1M cells (vs 2.6B) — no OOM; (c) is **FASTER** than the
> single-row full-width embed (~5s vs ~23s at log 6). **⇒ the make-or-break is
> RESOLVED: the integrated per-child verifier (channel + streamed embed + FRI +
> Merkle) stays ~log 14–15; pick L≈3.** **NEXT (the only remaining big piece):
> implement the general row-streaming `OodsEval` — a third `WitBackend` that
> captures each chip's `evaluate` as a computation graph (nodes + product-operand
> linear forms), schedules it into the windowed (row,col) layout (live-set ≤ W via
> lazy mask reads), + a matching streamed VerifyBackend; drive all 31; match the
> global composition; then bind the streamed `rc`/lookup-elements to the channel
> latches.** Both the offset mechanism AND the shape tractability are now de-risked.
>
> **LAYOUT DECIDED + EMISSION MECHANISM DE-RISKED 2026-06-19 (commits `cd4aac6`/
> `3cf4c9d`/`692b3f3`, `voucher-state-transition`, LOCAL) — the row-streaming
> OodsEval's two open unknowns (the layout, and the variable-offset read) are both
> RESOLVED; what remains is the emission engineering, not research.** Three gates,
> all dataflow-only (no proving for #0/#1, fast prove for the mechanism):
> - **Task #0 — flat-schedule BANDWIDTH measured (`tests/recursion_stream_bandwidth.rs`,
>   `BandwidthBackend` in `oods_auto.rs`).** A dataflow-only `WitBackend` walks all
>   31 chips through `drive_multi` (the schedule shape is value-independent, so no
>   masks/proof needed) and tracks each node's operand support, EXCLUDING latched
>   aux (rc/dinv/ox/comp — held on every row, zero distance). Real flat schedule:
>   **40138 streamed nodes** (16844 mask samples + 23294 witnessed products = 160552
>   M31, matches the prior 40150/160600 EXACTLY ⇒ the walk is faithful). **Operand
>   bandwidth is LARGE**: max distance **9785**, mean 2082, 65.8% of products reach
>   >256 nodes back (worst: Blake2bBoundary 9785, Blake2b 8856, Ristretto 6230) —
>   the chips read masks up front (`TraceEval::new`) and use them far downstream, so
>   small fixed offsets do NOT suffice. **Live-set width W**: naive 2903, lazy (defer
>   each mask read to first use) **1700**. ⇒ a pure register-WINDOW (no replication)
>   needs ~1700 lanes (≈6800 M31/row) — the acc chain serializes the constraints, so
>   shared mask samples stay live across them; lazy-W≈1700 is essentially inherent.
>   This REVISES the `recursion_stream_scale` optimism (68 cols/row modeled fresh
>   per-row inputs, bandwidth 1 — not the real shared-mask DAG).
> - **Task #1 — OODS DAG captured + LAYOUT decided: CO-LOCATE
>   (`tests/recursion_stream_layout.rs`, `GraphBackend` in `oods_auto.rs`).**
>   `GraphBackend` captures the full DAG (node kinds + per-product operand deps); the
>   test costs both candidate layouts from the real graph. **Co-locate wins
>   decisively**: replicate each mask sample onto the rows that CONSUME it (read at
>   offset 0) and keep only PRODUCT values cross-row. Measured: **product-only
>   live-set W_p = 65** (the lane count, vs ~1700 for a pure window — products are
>   short-lived, the Horner collapses each into the next step); **product→product
>   offset reach: max 64, mean 9, p99 53** (a bounded, small offset set — the offset
>   spike already proved offsets ≤ N/2 read the exact row); **product fan-in mean
>   1.0** (each product reads ~1 product operand = the acc lane, + latched rc), max
>   33; mask replication Σ = 79035 (avg 3.39/product) ⇒ storage ≈ 102329 QM31,
>   fitting log 14 at OPS_PER_ROW≈7, narrow (a handful of QM31/row + bounded offset
>   reads + latched). At OPS=8 the product reach ≤64 rank ⇒ ≤ ~8 ROWS.
> - **Task #1 — variable-offset EMISSION MECHANISM de-risked
>   (`tests/recursion_stream_route_spike.rs`).** The unsolved piece (neither
>   offset_spike nor stream_scale covered it): different products read DIFFERENT
>   past offsets with DIFFERENT coefficients, but a uniform AIR applies ONE fixed
>   constraint to every row. **Resolution PROVEN: the schedule is FIXED across all
>   canonical segments** (same 31 chips, same constraint structure, same mask shape —
>   only the OODS VALUES differ per proof; log_size only moves the cumsum_shift/dinv
>   *values*, not the shape), so the routing is PREPROCESSED. Each row reads the
>   stream column at a fixed window `[0,-D]` and reconstructs an operand as
>   `a = Σ_{k=1}^{D} ca[k]·sample(-k)` with `ca[k]` preprocessed (mostly zero — only
>   this row's actual operand offsets nonzero). `ca·sample` = preproc(deg1)·main(deg1)
>   = deg2; the whole sum is ONE deg-2 constraint (TERM COUNT IS FREE — only
>   multiplicative degree is bounded; verified against stwo's `expr/degree.rs`).
>   Reconstruction + product constraints stay UNGATED (hold on seed/padding rows
>   where columns are zero); only the linear chain `active·(s−p)` is gated (deg-1
>   selector × deg-1 diff = deg2 — gating a deg-2 expr would be deg 3, OVER the
>   bound). GATE: `route_air_satisfied` (assert, log 6) + `route_gate` (prove+verify
>   at log 8, ~90s honest, tamper rejected) GREEN. CRITICAL GOTCHA confirmed:
>   `assert_constraints_on_trace` checks only ZERO-ness, NOT the degree bound (a
>   degree-3 slip surfaces only as a FRI failure at prove/verify), so the PROVE is
>   what confirms degree ≤ 2 — every streamed-layout gate MUST prove, not just assert.
> ⇒ **the row-streaming OodsEval is now an ENGINEERING task, fully de-risked**: the
> layout (co-locate, W_p=65, masks replicated on-row, products at offsets ≤64 rank /
> ≤~8 rows at OPS=8) AND the read mechanism (preprocessed-coefficient windowed
> reconstruction, degree ≤ 2) are both proven. The remaining build = the StreamBackend
> EMISSION: a `WitBackend` whose V is a SYMBOLIC linear form (`Σ coeff·node + latched
> + const`, NOT an eager EF expression — the existing `VerifyBackend` binds operands
> at offset 0 at creation, which cannot stream); capture every product's two operand
> forms + the final equality; a host SCHEDULE pass laying products in walk order with
> mask-copies inlined adjacent to consumers + computing each node's (row, offset);
> a host TRACE fill (the OODS values into the stream + the preprocessed coeff/active
> columns = the fixed "program"); a streamed `FrameworkEval` reconstructing each
> product `w == a·b` from the windowed reads via the preprocessed coeffs (the spike's
> mechanism, scaled to ~8-row windows + the acc lane). GATE: drive all 31 via
> `drive_multi`/`drive_chip_oods`, match the global `PointEvaluationAccumulator`
> (assert) THEN prove+verify (degree), MEASURE rows/width/time; then bind the streamed
> `rc`/lookup-z/alpha to the channel-latched challenges (the join_assembly latch).
>
> **EMISSION CAPTURE + SCHEDULE BUILT + CHARACTERISED 2026-06-19 (commits `ff64c60`/
> `d86b8ef`+sweep, LOCAL).** The StreamBackend emission's host half is built and
> validated (no proving yet); the schedule layout is fully characterised.
> - **`StreamBackend` (symbolic capture, `oods_auto.rs`) + `recursion_stream_capture.rs`:**
>   a `WitBackend` whose V is a `StreamForm` (`Σ coeff·node + Σ d·latched + const` +
>   the concrete value), capturing each product's two operand forms (eager EF can't
>   stream — the read must defer to the consuming row). Host gate: every operand form
>   reconstructs its value, every product = a·b, the final equality reproduces the
>   global `PointEvaluationAccumulator`. 40139 nodes (16844 masks + 23295 products).
>   **FINDING: max operand form = 265 node terms** (a constraint summing ~256 witnessed
>   products) ⇒ no dense per-operand window-coeff vector; reconstruct big operands as
>   PARTIAL-SUM CHAINS.
> - **`StreamCapture::schedule` (chain-VM) + `Schedule::interpret`:** compiles the
>   capture to a flat micro-op stream (`CellOp` = Leaf | Mac | Mul): products in
>   capture order, each operand form a Mac chain (≤T terms/cell) over fresh Leaf copies
>   of mask operands (co-located) + prior Mul cells; the interpreter reproduces the
>   global composition for every T. **MEASURED (sweep T∈{2..256}, OPS=8):** 156–185k
>   cells → log 15; window reach 223→**151 rows floor** (1201 cells) — set
>   structurally by big-operand leaf spans + product-operand rank-spans inflated by
>   interspersed leaf/mac cells, NOT chain length. **A single flat stream's window is
>   too deep for a dense per-cell coeff layout (≈151·OPS positions/cell ⇒ ~190M
>   preproc cells).**
> - **⇒ NEXT (the schedule's final form): TWO-STREAM / TYPED-LANE layout** — a compact
>   product-result stream R (one cell/product, read at bounded rank-offset ≤W_p=65) +
>   the working stream W (leaf/mac, small T ⇒ local reach ~2 rows). Bounds both windows
>   to ~tens of offsets (R window ≈ 65/OPS_R rows). Dense-coeff cost ≈ cells × window
>   ≈ tens of millions of preproc cells — tractable (matches the design's "WIDTH is the
>   cost, minutes/GB"), exact lane/window tuning is an optimisation. THEN: the streamed
>   `FrameworkEval` (route_spike windowed-coeff mechanism over the two streams), GATE
>   against the global composition (assert THEN prove — assert does NOT catch the
>   degree bound), MEASURE; then bind streamed rc/lookup-z/alpha to the channel latches.
>
> **TWO-STREAM SCHEDULE + STREAMED AIR — THE STANDALONE OODS-EMBED GATE IS GREEN
> 2026-06-19 (LOCAL). The session milestone: the full 31-component OODS composition
> re-evaluates in ONE uniform STREAMED component that proves+verifies at degree <= 2
> and shares the channel's row count (no longer pure width).**
> - **Two-stream schedule + co-locate layout (`oods_auto.rs` +
>   `recursion_stream_two.rs`).** `StreamCapture::schedule_two_stream(T)` routes
>   PRODUCTS to a compact result stream R (one cell/product) and leaf/mac scratch
>   to a working stream W; big operands (max 265 mask terms) pre-fold into mac
>   chains so every consumer recon reads <= T direct terms. `layout_colocate(ops_s,
>   nleaf)` is the DESIGN's chosen layout: macs + products share ONE dense stream
>   (`ops_s` slots/row, each slot `r = oa*ob`; a mac is the slot whose `ob`-recon is
>   the constant 1 so `r = oa`), masks ride OFFSET-0 as WIDTH on their consumer
>   slot's row (the 86k leaves become columns, not rows). Both interpreters
>   reproduce the global `PointEvaluationAccumulator`. (The first cut -- a spread
>   two-stream layout with leaves in their OWN rows -- was WRONG: it scattered R
>   (dr 75-426) and cost 370M-1.3B preproc; co-locate fixes it. Kept as the spread
>   `layout` baseline; `layout_colocate` is the AIR target.)
> - **Measured cost (`colocate_layout_and_cost`; the design's product-rank reach =
>   64 CONFIRMED from the raw capture -- mean 9, p99 53; avg 1.85 mask terms/operand,
>   only 2.6% > 8).** Sweet spot **T=16, ops_s=4 -> log 13 (6251 rows), dr=21,
>   nleaf=74, ~34M preproc M31 cells** -- vs the single-stream 151-row floor / ~190M,
>   squarely in the design's "tens of millions". Higher T cuts macs but clusters
>   leaves (nleaf grows); ops_s trades rows for width; preproc total ~ recon-cells *
>   window is roughly invariant (~ inherent).
> - **Streamed embed AIR (`recursion_stream_embed.rs`) -- GATE GREEN.** A uniform
>   windowed-recon `FrameworkEval` generalising the route-spike to the two streams:
>   per row OPS_S product slots, each `oa`/`ob` RECONSTRUCTED from the window
>   (offset-0 co-located leaves + the dense stream read at `[0,-DR]` + offset-0
>   latched OODS scalars) via PREPROCESSED coefficients (the schedule is fixed
>   across canonical segments -- only OODS VALUES differ), then `r = oa*ob`; the
>   final slot carries `lhs - rhs` (gated `is_final*r == 0`); latched held constant
>   by `not_last`. Every constraint <= degree 2 (recon = preproc*main deg-2 sum, term
>   count free; products = main*main). Locked params T=16 / OPS_S=4 / DR=24 /
>   NLEAF=80. GATE: `assert_constraints` green on the REAL 31-component layout (412
>   main + 6149 preproc M31 cols/row), THEN **prove+verify GREEN at degree <= 2
>   (~72s release, `#[ignore]`) + a tampered cell rejected** -- the 160600-M31
>   single-row width DISTRIBUTED into a log-13 streamed layout that shares the
>   channel's rows. TWO gotchas closed: (1) `get_preprocessed_column` is
>   CURSOR-based (ignores the id) so the AIR MUST read preproc columns in EXACT
>   registration order (an order mismatch corrupted the coeffs on a band of rows,
>   invisible to a host read-back); (2) `assert_constraints` does NOT enforce the
>   degree bound -- only the PROVE confirms degree <= 2.
> - Shared synthetic setup extracted to `recursion_common::synth`
>   (`synthetic_setup` / `build_capture`), reused by every streamed gate.
> - **REAL-SEGMENT gate (`embed_gate_real`, `#[ignore]`, ~108s).** Drives the SAME
>   streamed embed on a REAL `prove_canonical` segment's OODS data (via
>   `reconstruct_oods_for_recursion`, the `oods_auto_real_segment` real-data path):
>   it proves+verifies + rejects a tamper, AND its co-locate layout shape is
>   **identical to the synthetic** (6251 rows, dr=21, max-leaf 74 all match) -- so
>   the routing "program" (the preprocessed coeff/selector columns) is genuinely
>   SEGMENT-INVARIANT, the property that lets it be PREPROCESSED across the 76
>   canonical segments. The streamed embed now runs on real data, not just the fuzz.
>
> **NEXT (precise, grounded):** (a) ✅ **DONE** — layout DECIDED (co-locate, W_p=65)
> + the variable-offset preprocessed-routing mechanism de-risked + the StreamBackend
> emission (two-stream schedule + co-locate layout + streamed FrameworkEval)
> PROVES+VERIFIES at degree <= 2 (above); remaining (b) bind the streamed
> embed's `rc` to
> the channel-latched composition coeff (the join_assembly latch pattern, scaled);
> (c) ✅ **DONE (step 1b)** — `extract_recursion_data` gives the full FRI/decommit
> data via the PUBLIC `fri_answers` + `FriVerifier`/`tree.verify` calls (no need to
> replicate `compute_decommitment_positions_and_rebuild_evals` —
> `fri_answers` already produces the first-layer evals; the in-AIR fold chain does
> the rest of the reconstruction); (d) scale the FRI fold chain (14 layers, 38
> queries — feed `data.first_layer_evals` + `data.fold_alphas` + `data.query_positions`)
> + the 4-trace + 14-FRI-layer Merkle decommit (generalise the leaf sponge for the
> non-8-multiple QM31-wide FRI leaves — the partial-rate `finalize` pad); (e)
> boundary + claimed-sum balance (`boundary_binding::check_boundary_claimed_sums`,
> scale-free; uses `data.lookup_elements` + the public boundary states).
>
> **PER-CHILD ASSEMBLY STEPS 1 + 1b + HARDENING + 4a + 4b LANDED 2026-06-19/20
> (LOCAL, `tests/recursion_child_assembly.rs`, commits `79fca73` / `461f0a8` /
> `1de6f70` / `cf157ec` / `f8e896b`).** The channel transcript replay and the
> streamed OODS embed now co-exist in ONE uniform `FrameworkEval`, driven off ONE
> real `prove_canonical` segment, with the cross-chip latch bindings + the
> claimed-sum balance + the boundary public-input recompute (the federation cash-in)
> live at canonical scale. The honest gate proves+verifies @ **log 14,
> ~82–94s/prove**; every tamper (transcript / embed / oods_t / mis-placed indicator
> / claimed_sum / wrong boundary state) is rejected.
> - **Step 1 (rc latch):** the merged component reads the channel block (the proven
>   `join_assembly` AIR) AND the streamed embed block (the proven
>   `recursion_stream_embed` AIR) on a shared row grid (the embed's 6251 stream rows
>   ride within the channel's 16384), sharing `not_last` (channel digest chain +
>   embed latched constancy) and the storage indexing. The embed's `rc` latched
>   column (`latched[0]`) is BOUND to the channel's composition-`random_coeff`
>   squeeze via an `is_rc_draw` preprocessed indicator (the first `Squeeze` at/after
>   `prefix_len`): `is_rc_draw·(lat_rc[j] − squeeze_out[j]) == 0`, degree 2. GATE
>   GREEN @ **log 14**, ~90s/prove (283s for honest + 2 tampers): proves+verifies;
>   a tampered transcript value AND a tampered embed value are rejected.
> - **Step 1b (in-circuit OODS-point derivation):** `dinv` (`latched[1]`) and `ox`
>   (`latched[2]`) are no longer trusted host inputs — they are DERIVED in-AIR from
>   a latched `oods_t` (bound to its squeeze, the 2nd `Squeeze` at/after
>   `prefix_len`, via `is_oods_draw`): the `get_random_point` map (`x=(1−t²)·inv,
>   y=2t·inv`), then `ox = double_x^{mlbd-1}(oods.x)` (each `double_x(x)=2x²−1`
>   step's square witnessed) and `dinv = 1/coset_vanishing(coset, oods)` (shift by
>   the fixed coset point `C = step_size.half().to_point() − coset.initial` of
>   `CanonicCoset::new(mlbd).coset`, then the same `double_x` chain). `mlbd=14 ⇒
>   dbl_steps=13`; all constraints degree ≤ 2; `mlbd`/`oods_point`/transcript come
>   from `extract_recursion_data`. GATE GREEN @ **log 14**, ~87s/prove (347s for
>   honest + 3 tampers): a tampered `oods_t` is rejected, isolating the new
>   derivation (only it reads `oods_t`). ⇒ `rc`/`dinv`/`ox` are all now
>   transcript-derived; `comp` (`latched[3..11]`) + the lookup elements + the embed
>   LEAVES remain host-supplied (bound via the FRI/DEEP + Merkle path, steps 2–3).
> - **Draw-indicator hardening (review follow-up, `1de6f70`):** an adversarial
>   multi-agent review flagged that the `is_rc_draw`/`is_oods_draw` indicators are
>   PREPROCESSED columns, so the latch bindings rest on the preprocessed trace being
>   correct, and nothing in-AIR forced them to fire on a genuine `Squeeze` row.
>   Resolution: the indicators are part of the fixed verifier-program identity
>   (pinned in the full recursion by the W0 commitment allowlist — exactly as
>   `is_first`/`not_last`/the recon-routing program are), so WHICH squeeze they
>   select is program-pinned; the AIR now additionally enforces `is_X_draw·(1 −
>   is_squeeze) == 0` so a mis-placed indicator cannot bind rc/oods_t to a
>   non-challenge Absorb/Pow perm output. New reject test (mis-placed indicator).
> - **Step 4a (claimed-sum balance):** the 31 per-component `claimed_sums` are bound
>   to the channel's `mix_felts(claimed_sums)` absorb — the last 16 RATE-8 prefix
>   perms before the interaction commit (`records[prefix_len-17..prefix_len-1]`),
>   chunk `c` carrying `claimed_sum[2c]`/`[2c+1]` in `absorbed[0..4]`/`[4..8]` (each
>   QM31's 4 coords never cross an 8-boundary) — and `Σ claimed_sums == 0` is
>   enforced in-AIR (the global logup-balance check, `verify.rs:299`). 31 latched cs
>   columns + 16 `is_cs_chunk` preprocessed indicators (each hardened to fire only on
>   a genuine Absorb row). The channel already constrains `absorbed` to the mixed
>   value, so the binding pins cs to the real claimed_sums. GATE GREEN @ **log 14**
>   (491s / 6 proves, corrupted-claimed_sum rejected).
> - **Step 4b (boundary public-input recompute — the federation cash-in):** the 4
>   boundary chips' claimed sums are RECOMPUTED in-AIR from the PUBLIC boundary
>   states (initial/final registers, pc, ts, memory roots) and each compared to its
>   (step-4a-bound) `claimed_sum` — binding the io-hash (`final.registers[9..13]`) +
>   the memory roots (`verify.rs:318` → `check_boundary_claimed_sums`). Each sum is
>   `Σ 1/⟨z, tuple⟩`, `⟨z, tuple⟩ = Σ alpha^i·tuple_i − z`; the 3 relations
>   (register-memory 18, program-execution 12, merkle-node 66) have their `(z,
>   alpha)` latched to their draw squeezes (each from ONE `draw_secure_felts(2)`:
>   `z=out[0..4]`, `alpha=out[4..8]`, matched to the squeeze by value), `alpha`-powers
>   derived in-AIR (witnessed chain), each `1/⟨z, tuple⟩` a witnessed inverse; the
>   boundary states are public AIR constants. New crate accessor
>   `boundary_relation_challenges`. All degree ≤ 2. GATE GREEN @ **log 14** (622s / 7
>   proves; a WRONG claimed memory root is rejected). REMAINING follow-on (not a new
>   gap): connect the embed's BAKED claimed_sums + lookup elements to these bound
>   columns (the embed leaves bind via Merkle, steps 2–3).
>
> **STEPS 2+3 FOUNDATION + THE MAKE-OR-BREAK MEASUREMENT — 2026-06-21 (LOCAL,
> commits `4c9c073` / `58d3b66`).** The shared-perm-block crux is PROVEN and the
> real per-child scale is MEASURED. Net: the architecture works, the per-child is
> **log 17 (not the predicted 15)** because the trace-tree LEAF SPONGE dominates,
> and it is **tractable (~20–25 GiB extrapolated) on this 62 GiB box** — the design
> cost model was ~3.7× low on perms (and 12× low on the trace-tree term).
> - **Shared-perm-block crux PROVEN (`tests/recursion_shared_perm.rs`,
>   `shared_perm_gate`, ~4s).** The Merkle decommit STREAMS to ONE perm/row: the
>   leaf sponge (`update_leaf` absorbs + the padded `finalize`) and every
>   `hash_children` level are each their OWN row, the 16-wide sponge/hash state
>   threaded row→row by a `[0,1]` latch on dedicated `st` columns (the channel's
>   digest-chain mechanism). A preprocessed row-type selector
>   (`is_tr`/`m_abs`/`m_final`/`m_node`/…) shares the `eval_permutation` slot
>   between a channel-transcript perm and a Merkle perm. The bit-driven
>   `hash_children` child ordering (degree 3 = `m_node·bit·sib`) is lowered to
>   degree 2 by a WITNESSED `mux = bit·(sib − cur)` (`left = cur+mux`,
>   `right = sib−mux`). A real proof's main trace-tree decommit re-hashes to its
>   real root in this streamed form, shares the perm slot with a transcript region,
>   proves+verifies at degree ≤ 2; tampered leaf / sibling / transcript rejected.
> - **Adversarial review CLEAN (Workflow, 4 lenses + per-finding verify):
>   `confirmed: []`.** Every finding dismissed as an intended scope caveat or a
>   documented follow-on. The dismissed set IS the integration-obligation checklist
>   (carry into the assembly): (a) the streamed transcript is a stand-in — the REAL
>   channel⊕embed coexistence on one perm is already proven in the landed assembly,
>   so gating it by `is_transcript` follows the proven pattern; (b) the 4-wide QM31
>   FRI-layer leaves need the partial-rate `finalize` generalization — **AND** stwo
>   packs FRI leaves when `log_size ≥ LOG_PACKED_LEAF_SIZE && fold_step>1`
>   (`prover/fri.rs:296-302`), so the leaf shape must handle BOTH packed and
>   unpacked partial-rate; (c) the per-tree ROOTS must bind to the channel's
>   commit-absorb rows (not be host constants); (d) the decommit LEAF VALUES must
>   bind to the embed's OODS sampled values / the `mix_felts(sampled_values)`
>   absorb (else a prover decommits arbitrary leaves) — the deepest obligation; (e)
>   the routing is segment-invariant ONLY for per-path-INDEPENDENT streaming (no
>   co-queried subpath sharing) — which is what we do (the schedule is fixed by the
>   canonical profile; only values/bits differ per segment).
> - **Streamed multi-tree decommit VALIDATED on REAL data
>   (`tests/recursion_decommit_scale.rs`).** Generalised to the 4 real trace trees:
>   per-tree widths/heights, MIXED-DEGREE leaves (the lifted Merkle hashes each leaf
>   row with columns sorted ASCENDING by log size — `extract_recursion_data` now
>   returns `tree_heights` + `tree_column_log_sizes`), partial-rate finalize for
>   non-8-multiple widths. `decommit_streamed_assert`: ALL 4 real trees (preproc
>   452, main 9951, interaction 5364, composition 8 cols; height 16) re-hash to
>   their real roots. `decommit_streamed_prove`: narrow trees prove+verify at
>   degree ≤ 2, tampered chunk/sibling rejected. `decommit_streamed_prove_main`:
>   the WIDE main-tree decommit (log 16, 47880 perms) proves at **1.3 GiB peak
>   RSS** — a decommit-only component is CHEAP even when tall (its preproc is ~14
>   narrow cols).
> - **THE MEASUREMENT (`decommit_scale_measure`, real canonical segment).**
>   Per-child perm budget: **transcript 8584 + trace-tree 77444 + FRI-layer 1640 =
>   ~87.7K → log 17.** Breakdown that corrects the design:
>   - **Trace-tree = 77444 perms, NOT ~6.2K (12× low).** The killer is the LEAF
>     SPONGE over the WIDE trace: tree 1 (main) 9951 cols → 1244 leaf perms/leaf ×
>     38 = 47880; tree 2 (interaction) 5364 cols → 26106; tree 0 (preproc) 2774;
>     tree 3 (composition, 8 cols) 684. Node hashing is only ~2.4K (38×16×4). The
>     leaf width = the FULL 31-component trace column count and is ~fixed by the AIR
>     (independent of segment step count — more steps = more ROWS, same columns).
>   - **FRI-layer = 1640 (hash_witness), CHEAPER than the ~8.7K estimate** (14
>     layers, last_layer degree-0, 38 queries halving per layer).
>   - All 38 query positions distinct (no collisions); all trace trees height 16
>     (= `lifting_log_size`); `max_log_degree_bound`=14.
> - **TRACTABILITY (revised — the earlier "intractable" fear was based on a wrong
>   "tens of GB at log 14" assumption; that figure was the multi-million-step
>   CAPSTONE, not this assembly).** Measured: channel+embed assembly at log 14 =
>   **2.2 GiB** peak; main-tree decommit at log 16 = **1.3 GiB**. Peak RSS ≈
>   (preproc+main cols)×2^(log+blowup). Combined log-17 per-child ≈ (6163 preproc +
>   1997 main) × 2^19 ≈ 4.3B cells → **~20–25 GiB, ~12–15 min** (scalar hasher) —
>   FEASIBLE on this 62 GiB box (after reclaiming cache). The cost DRIVER to watch
>   is the EMBED's ~6149-wide preproc replicated across the decommit's ~131K rows
>   in ONE uniform component (the decommit alone is narrow+cheap; the embed alone is
>   wide+short; the uniform component pays width×rows). **Implication for the
>   fold-up:** the 2-child join (P5.4) ~doubles → log 18 / ~40–50 GiB (borderline on
>   62 GiB); higher fold levels need more RAM or **P5-perf (SIMD Poseidon2-M31
>   commit) becomes important — promote it from "optional" toward a prerequisite for
>   P5.4/P5.5.** A trace-width reduction (the 9951+5364 main+interaction leaves) or a
>   narrower embed-routing preproc would also help and is worth a design pass.
>
> - **FRI fold chain at REAL scale PROVEN (`tests/recursion_fri_chain_real.rs`,
>   commits `378042f` host + `182d969` AIR).** Generalises the proven
>   `fri_fold_chain.rs` to the real segment's **14 layers (1 circle + 13 line), 38
>   queries**: a HOST reconstruction replays the verifier's per-layer fold from
>   `extract_recursion_data` (`first_layer_evals` + `fold_alphas` +
>   `query_positions`) + the raw `fri_witness` siblings — every query folds down to
>   the degree-0 last-layer constant, matching the real `FriVerifier::decommit`
>   (de-risks the per-layer indexing). The in-AIR chain (575 cols/row, log 6)
>   derives each layer's twiddle from the bound q-bits via the proven point-chain
>   gadget, folds with the constant per-layer `fold_alpha`, chains `folded[L]` into
>   layer L+1, and checks the last-layer constant — proves+verifies at degree ≤ 2,
>   perturbed fold rejected (`fri_chain_real_gate`). **fold_step=1 throughout ⇒ the
>   FRI-layer leaves are 4-wide QM31 (no packing), so the FRI-layer Merkle decommit
>   needs NO new gadget — the streamed decommit (`recursion_decommit_scale`) applies
>   directly (`leaf_chunks` already handles the rem=4 partial-rate finalize).**
>   ⇒ **all per-child verifier MECHANISMS are now proven standalone** (channel,
>   OODS embed, streamed trace-tree decommit, shared perm block, FRI fold chain,
>   FRI-layer decommit); the only remaining mechanism is the **DEEP-quotient
>   reconstruction** (`fri_answers`: leaves + OODS samples → `first_layer_evals` =
>   obligation (d)).
>
> - **DEEP-quotient reconstruction host-first DONE (`tests/recursion_deep_quotient.rs`,
>   commit `f451bc5`).** `extract_recursion_data` now exposes the `fri_answers`
>   decomposition in AIR-friendly form (`RecursionData.deep_batches` + `DeepBatch`):
>   the sample batches grouped by sample point, each carrying per-column the
>   FLATTENED column index + the complex-conjugate line coefficients `(a, b, c)`
>   (via stwo's `build_samples_with_randomness_and_periodicity` +
>   `ColumnSampleBatch` + `column_line_coeffs`). The host re-derives
>   `accumulate_row_quotients` from that + the real `queried_values` + per-query
>   domain points and MATCHES stwo's `first_layer_evals` for all 38 queries — the
>   formula + constants validated in the in-AIR form: per query at `p`, `eval =
>   Σ_batch (1/line(z,z̄)(p)) · Σ_col (queried[col]·c − (a·p.y + b))`, with the CM31
>   denominator inverse witnessed (deg 2), the numerator a degree-1 sum over the
>   leaves (term count FREE), the product degree 2. Real shape: **11 sample batches,
>   17929 (batch,column) numerator terms**. The numerator reads the SAME leaves the
>   trace-tree decommit binds ⇒ the in-AIR DEEP rides on the decommit's streamed leaf
>   rows (an accumulator column + per-row `leaf·c` contributions; ~17929·38 deg-1
>   adds + 11·38 witnessed CM31 inverses), so it is naturally part of step 5, not a
>   separate component.
> - **⇒ ALL per-child verifier mechanisms are now de-risked** (formulas validated,
>   AIRs proven where standalone-meaningful): channel, OODS embed, streamed
>   trace-tree decommit, shared perm block, FRI fold chain, FRI-layer decommit, DEEP
>   quotient. The remaining work is the **step-5 INTEGRATION** (no unknown
>   mechanisms left).
> - **The full single-child verifier (step 5) is the final BUILD** — fold the
>   validated streamed multi-tree decommit + the FRI fold chain + the FRI-layer
>   decommit + the DEEP reconstruction into the assembly's `ChildEval`, gating the
>   channel by `is_transcript`, discharging integration obligations (a)–(e) above
>   (esp. (c) root↔commit-absorb and (d) leaf↔OODS-sample binding), and PROVE the
>   combined log-17 component
>   (~20–25 GiB). The scale + memory are now KNOWN; the mechanisms are PROVEN
>   standalone; this session de-risked the make-or-break.
> - **Steps 2 + 3 (FRI fold chain + multi-tree Merkle decommit) are a COUPLED
>   subsystem that only becomes SOUND TOGETHER**, and they need a **shared perm
>   block**: ONE `eval_permutation` per row, a row-type selector choosing between a
>   channel-transcript perm and a Merkle `hash_children` perm. The Merkle decommit
>   perms (~8.7K FRI-layer + ~6.2K trace-tree) EXTEND the perm-row count to ~23.5K
>   ⇒ **log 15** (≤ canonical 19). The FRI fold chain's per-layer SIBLINGS come from
>   the FRI-layer Merkle decommit (`fri_witness`) and its layer-0 input
>   (`fri_answers` / `data.first_layer_evals`) from the trace-tree decommit's
>   `queried_values` — so building the FRI fold chain WITHOUT the Merkle decommit
>   adds columns but no soundness (the mechanism alone is already proven in
>   `fri_fold_chain.rs`). Latch the 14 `fold_alphas` (the 4th..17th `Squeeze`
>   at/after `prefix_len`) to the channel; last layer = degree-0 constant. **This
>   shared-perm-block unification is the architectural crux of the full assembly and
>   the right thing to de-risk next.**
> - **Step 4 (claimed-sum balance) is INDEPENDENT** of FRI/Merkle — it rides log 14
>   (no new perm-rows) and is the federation cash-in (binds the public boundary
>   states = io-hash in `final.registers[9..13]` + memory roots). Mechanism: bind
>   the 31 `claimed_sums` to the channel `mix_felts(claimed_sums)` absorb (16 absorb
>   records, the `fixed_point_join` commit-absorb bind pattern), bind the 3 boundary
>   relations' lookup elements (`RegisterMemory`/`ProgramExecution`/`MerkleNode`) to
>   their draw squeezes (each `relation!` draws `z,alpha` from ONE squeeze via
>   `draw_secure_felts(2)` ⇒ `z=out[0..4]`, `alpha=out[4..8]`; `alpha_powers`
>   derived in-AIR as witnessed products), then recompute
>   `check_boundary_claimed_sums` in-AIR (`combine = Σ alpha^i·tuple_i − z`,
>   witnessed inverses) + `claimed_sums.sum()==0`. Could land before steps 2+3.
> - **`comp` latch + embed leaves:** the embed's `comp` (`latched[3..11]`) is the
>   composition-tree OODS sampled values, and the leaves are the per-component OODS
>   sampled values — both absorbed via `mix_felts(sampled_values)` and verified by
>   the trace-tree Merkle decommit; they bind in step 3.
> - **`mlbd` segment-invariance caveat:** the test's tiny segment has `mlbd=14`; the
>   production 100k-step canonical segments share a (locked) profile ⇒ a fixed
>   `mlbd` across them, so `dbl_steps`/`C` are fixed AIR parameters there. The
>   `dbl_steps` loop is already runtime-parametric, so a different `mlbd` just
>   changes the chain length.
>
> **STEP 5 INTEGRATION UNDERWAY 2026-06-22 (LOCAL) — THE MAKE-OR-BREAK LOG-17
> PROVE IS GREEN AT 17.3 GiB.** New `tests/recursion_child_full.rs` folds the
> proven mechanisms into ONE uniform `ChildFullEval`, built incrementally on top of
> the proven `recursion_child_assembly` (which stays the log-14 regression gate):
> - **Step 1a (`12e03d0`) — `is_transcript` gating.** The channel block's
>   structural constraints fold behind a preprocessed `is_transcript`; the digest
>   chain uses a preprocessed `not_last_tr = is_transcript[i]·is_transcript[i+1]`
>   (deg 2); latched constancy keeps the FULL `not_last`. KEY deg-2 trick: terms
>   already carrying a transcript-only selector (is_absorb/is_squeeze/…) are 0 on
>   non-tr rows and need NO `is_transcript` factor; only the bare terms get it (else
>   selector·value·is_transcript = deg 3). Empty merkle ⇒ proves identically to the
>   assembly (the safe checkpoint freeing the perm slot). Gate GREEN log 14, 622s.
> - **Step 1b (`4579cfe`) — streamed merkle decommit shares the channel perm slot.**
>   A real composition-tree decommit (684 rows) rides the freed `eval_permutation`
>   via the `recursion_shared_perm`/`recursion_decommit_scale` gadget (m_*/zero_st/
>   hash_link/cap_fwd + st[16] [0,1]-latch + witnessed mux); is_transcript=1 binds
>   the channel init, m_*=1 binds the merkle init, the perm (init,out) is SHARED.
>   `gen_trace` restructured: transcript fill on 0..n_real, perm-only fill on the
>   merkle/padding rows. MK_COLS=41 inserted between the channel & embed blocks.
>   Gate GREEN log 14, 790s/9 proves (+ merkle leaf/sibling rejects).
> - **Step 2a (`17020f9`) — THE MAKE-OR-BREAK: full 4-tree decommit at log 17.**
>   `mk_resolve` streams ALL 4 real trace trees (77444 rows). The full per-child
>   verifier (channel 8584 + embed 6251 + 4-tree decommit 77444 + latches +
>   claimed-sum + boundary) proves+verifies a REAL segment in ONE uniform component
>   at degree ≤ 2. New `child_full_measure` (honest + 1 reject; the 9-tamper
>   `child_full_gate` is ~135 min at log 17 — kept for documentation; the non-merkle
>   tampers are proven at log 14 with identical constraints). **MEASURED: log 17
>   (131072 rows), 975 main / 6187 preproc M31 cols, PEAK RSS = 17.3 GiB (better
>   than the 20-25 GiB extrapolation), ~17-20 min/prove.** ⇒ tractable on this 62
>   GiB box; the 2-child join (P5.4) ≈ 2× → ~34 GiB (revised DOWN). **The central
>   de-risk is ANSWERED: the full per-child verifier fits + proves at log 17.**
> - **Step 2b — root↔commit-absorb (obligation c).** Each tree root is absorbed via
>   `mix_root` (root limbs in `absorbed`); latched `root_lat[4][8]` are bound to that
>   absorb (`is_root_absorb[t]`) and pin the decommit `dc_root` on the tree's root
>   rows (`is_root_t[t]`), so `out == dc_root == root_lat == the channel commitment`
>   — the decommit verifies against the TRANSCRIPT-FIXED commitment, not a free host
>   root. Assert GREEN log 17; the measured prove (honest + root-tamper) confirms it.
> - **REMAINING (step 3/4/5; all mechanisms PROVEN standalone):** (3) FRI fold chain
>   + FRI-layer decommit (latch the 14 `fold_alphas` = squeezes[3..17]; couple the
>   e0/e1 fold inputs to the FRI-layer decommit leaves); (4) the DEEP numerator
>   (obligation d, leaf↔OODS) over the trace-decommit leaves, bound to the fold
>   chain's layer-0 `first_layer_evals`; (5) the fully-combined log-17 prove +
>   adversarial review. Each is the same "add cols / gate / bind / assert / prove"
>   shape as steps 1-2; the ~17-20 min proves are the cost.

**GOAL.** Assemble P5.2's OODS embed + the real FRI fold chain (GATE 2 at the real 19-layer
scale) + the real multi-tree Merkle decommit (GATE 3 at the real 4-tree + FRI-layer-tree
scale) + the ChannelChip transcript replay, all against ONE real Poseidon2-M31 conservation
segment — the full per-child verifier-AIR at canonical scale. This is the make-or-break
MEASUREMENT the design has front-loaded (`recursion-design.md:170-175,197-199`).

**PREREQS.** P5.0 (real segment) + P5.2 (OODS embed). GATE 2/3/4 machinery.

**BUILD STEPS.**
1. Scale GATE 2's fold chain to the real FRI: ~19 layers, 38 queries, the real
   `fri_answers` first-layer evals (the DEEP-quotient chip feeds it).
2. Scale GATE 3's decommit to the 4 trace trees (preproc/main/interaction/composition) at
   real heights + the per-FRI-layer trees, leaves from the fold reconstruction.
3. Wire ChannelChip (full real transcript, ~397 perms) + the latched challenges driving all
   of the above + P5.2's OODS embed, in ONE uniform component. P5.2 ships
   `verify::reconstruct_oods_for_recursion` (the FS-transcript replay → per-component masks +
   `lookup_elements` + oods scalars + claimed_sums) and `framework_access::drive_chip_oods` +
   `oods_auto::drive_multi` (the all-31 continuous-Horner embed) — assemble these here; the
   latched challenges REPLACE the seam's host-replayed scalars with channel-derived ones.
4. Bind the real SegmentState boundary fields (the seam fields come from the real child's
   `initial_state`/`final_state`, `proof.rs:126-140`).
5. **Claimed-sum balance (moved from P5.2 — it's separate from the OODS re-eval):**
   `claimed_sums.sum()==0` (a degree-1 sum over the committed per-component claimed_sum
   columns) + the boundary-binding claimed sums (`verify.rs:316-327` →
   `boundary_binding::check_boundary_claimed_sums` — recompute the 4 boundary chips' sums as
   witnessed inverses of relation combines over the public boundary states), driven by the
   latched challenges. The `reconstruct_oods_for_recursion` seam already returns the real
   `claimed_sums` + `lookup_elements`.

**GREEN GATE.** The full single-child verifier-AIR proves+verifies a REAL canonical segment
end-to-end; **MEASURE its natural log_size, width, prove-time, and peak memory.** The design
predicts log ~14 (`perm_scale.rs`, `recursion-design.md:152-156`); confirm at the REAL
31-component scale (the prior gates ran a SMALL de-risk child). ACCEPT valid; REJECT a
tampered query/sample/path.

**GOTCHAS.** This is where the ~16K-perm scale (8,664 FRI-Merkle + 3,192 trace-tree + ~3,040
leaf + ~397 transcript) becomes real (`recursion-design.md:75-83`). Prove ≈ minutes; peak
memory tens of GB (scalar hasher, CpuBackend — grounding §perf.4). Validate with
`assert_constraints` BEFORE every slow prove.

**COST.** ~1–2 sessions (assembly + the slow measurement loop). The prove iterations are the
slow part — lean hard on `assert_constraints`.

**START HERE.** `recursion-design.md:73-99` (the cost model + the 2 structural facts) +
`verifier_air_integration.rs` (the integration template) + the GATE 2/3/4 files.

---

## Session P5.4 — the real 2-child fixed-point join

**GOAL.** Combine P4.2's fixed-point STRUCTURE (2 children + seam + allowlist + aggregate
public inputs) with P5.3's full per-child DEPTH + bind the REAL seam (the page-Merkle
`memory_root` + pc/ts/registers from real children) + the real `{C_0,C_1}` (P2Hash
commitments). The genuine recursion node at canonical scale.

**PREREQS.** P5.1 (`{C_0,C_1}` re-pinned) + P5.3 (real per-child depth).

**BUILD STEPS.**
1. Two real Poseidon2-M31 conservation segments as children (e.g. one comb-free `C_0`
   segment + the one comb `C_1` segment — exercises both allowlist entries).
2. Generalize P5.3's single-child verifier to TWO children with P4.2's per-child anchor/break
   (`is_child_start`/`chain_ok`).
3. Bind the REAL seam: `child_L.final_state == child_R.initial_state` on the 4 bound fields,
   where `memory_root` is the real page-Merkle root (`proof.rs:138`, the
   `Memory{Page,Merkle,RootBoundary}` + `Blake2bBoundary` chips are already IN the 31
   components P5.2 embeds — so the seam binds to genuinely-verified roots).
4. Allowlist: each child's `commitments[0]` (P2Hash) bound at its commit-absorb row ∈
   `{C_0,C_1}` (the real re-pinned const).
5. Aggregate public inputs: `expected_initial_root` = left child `initial_state.memory_root`,
   `final_memory_root` = right child `final_state.memory_root`, `io_hash` = right child
   `registers[9..13]` (`proof.rs:210-216`).

**GREEN GATE.** A real 2-child join (two real segments) proves+verifies through the lifted
protocol; the real seam + real allowlist + aggregate public inputs bound; **MEASURE log_size
(~15 predicted) + prove-time + memory.** Tamper: broken seam, out-of-allowlist child,
tampered child proof — each rejected.

**GOTCHAS.** Two children ≈ 2× the perm count → log ~15, ~5 min/join (extrapolated, scalar
hasher). Memory ~tens of GB. The fixed point requires the join's OWN proof to re-verify at
the same canonical shape — confirm (it's the recursion invariant; P4.2 showed it structurally,
this confirms at real depth).

**COST.** ~1–2 sessions. Slowest proves yet (log ~15 at full 31-comp width).

**START HERE.** `fixed_point_join.rs` (P4.2 structure) + P5.3's single-child verifier.

---

## Session P5.5 — tree driver + fold 76 → aggregate + `verify_aggregate`

**GOAL.** The offline scheduler that folds the 76 real segments up the depth-7 binary tree
into ONE aggregate proof, and `verify_aggregate` replacing
`verify_chain_standalone_allowlist` + io-binding.

**PREREQS.** P5.4 (the real join node). P5.1 (allowlist).

**BUILD STEPS.**
1. **Lift decision:** if a raw segment proof's shape ≠ the join's child shape, build a thin
   LIFT-AIR normalizing a segment into join shape at the leaves (`recursion-design.md:40-41,
   206-208`); else the join verifies segments directly (single uniform shape — preferred).
2. **Offline scheduler:** level-0 = 38 parallel leaf joins (each folds 2 segments), fold up
   7 levels; the critical path is 7 sequential joins (~35 min–1 hr extrapolated; the 38
   leaves parallel across boxes, grounding §perf.4). Extend `prove_chain_segments`
   (`examples/extensions/prover/src/lib.rs:327`) → `aggregate_chain_segments`.
3. **`verify_aggregate(expected_initial_root, final_memory_root, io_hash, allowlist)`** over
   the ONE aggregate proof — replaces the N-segment loop while preserving the 4-part public
   contract (grounding §allowlist.3): anchor `proofs[0].initial.memory_root` ↦
   `root.left_boundary.memory_root`; final root ↦ `root.right_boundary.memory_root`; io_hash
   ↦ `root.right_boundary.registers[9..13]`; per-segment allowlist membership folded in-circuit.
4. **Wire the federation LIVE path:** the bridge's `verify_chain` (`clerk-bridge:736-775`) +
   `verify_chain_segments` (`prover:380-432`) become `verify_aggregate` over one proof + manifest.

**GREEN GATE.** 76 real segments → one aggregate proof; `verify_aggregate` ≡ today's
`verify_chain_standalone_allowlist` + io-binding (same accept/reject on the same inputs);
the federation e2e (`clerk_ledger_two_bank_federation`) green over the aggregate; aggregate
size ~1–2 MiB (vs 227 MiB chain).

**GOTCHAS.** The aggregate proof must itself be a valid child shape (the fixed point) so a
future settlement venue verifies ONE canonical STARK. Memory across the 38 parallel leaves
multiplies the per-join RAM — prover-fleet sizing. `N` never appears in `verify_aggregate`
(constant-size, N-free — `recursion-design.md:59-71`).

**COST.** ~1–2 sessions (scheduler + the e2e). The full 76-segment aggregate is the heaviest
run — likely a long offline batch.

**START HERE.** `recursion-design.md:39-71` (tree topology + aggregate public inputs) +
`prove_chain_segments`/`verify_chain_segments` (`prover/src/lib.rs:327-432`).

---

## P5-perf (parallel, optional) — SimdBackend Poseidon2-M31 commit op

**GOAL.** The single biggest prove-time lever: a `SimdBackend` `MerkleOpsLifted` /
`BackendForChannel<P2MerkleChannel>` impl, so segments AND joins commit on packed-M31 SIMD
lanes instead of the scalar hasher (grounding §perf.2 — the scalar hasher is ~99.5% of the
prove cost and CpuBackend-only today).

**BUILD STEPS.** Port the scalar `permute`/`hash_children_m31` (`recursion_common/mod.rs:132-227`)
to packed-M31 SIMD lanes in the stwo fork; wire `BackendForChannel<P2MerkleChannel> for
SimdBackend`. Then D1-A's CpuBackend retarget can be reverted to SimdBackend for both
segments and joins.

**GREEN GATE.** A segment (and a join) proves+verifies on SimdBackend under Poseidon2-M31,
measurably faster than the scalar path.

**GOTCHAS.** Fork-level backend engineering; net-new crypto-backend code; not on any tracked
path. Independent of correctness — defer until fleet throughput demands it.

**COST.** ~1–2 sessions, isolated. Can run any time after P5.0.

---

## Cross-cutting reminders (carry into every session)

- **`assert_constraints_on_trace` (fast, AssertEvaluator) BEFORE every slow prove** — the
  proves are minutes-to-tens-of-minutes at canonical scale; never burn a prove on a
  constraint bug a fast assert catches.
- **ONE uniform component, no producer/consumer split** (the split is a real residual
  custom-stack bug). Latched challenge columns (the channel's `[0,1]` cross-row mask) are the
  cross-chip propagation mechanism — proven in P4.
- **`cargo clean -p stwo` on inexplicable `ConstraintsNotSatisfied`** (stale-rlib gotcha).
- **fmt + clippy on the pinned `nightly-2025-05-09`** (stwo uses nightly features); vos
  commits stay LOCAL, `--no-verify`, NEVER Co-Authored-By.
- **Format version + re-bake ordering:** bump `PROOF_FORMAT_VERSION` once in P5.0; re-bake
  `{C_0,C_1}` once in P5.1 AFTER vetted constants (D2) — re-baking before the real constants
  wastes a re-bake.
- **The unmeasured risk is WIDTH, not depth:** log_size is proven ≤ 19; the 530-site OODS
  embed + the full 4-tree decommit add columns/row, raising per-cell prove cost. P5.2/P5.3
  measure it. If a single join's width makes proving intractable, the fallback is a
  compression layer or a bigger canonical shape (`recursion-design.md:173-175`) — a decision
  point gated by the P5.3 measurement.
- **Settlement venue (the recursion-verifier crate) is P6**, not P5 — wasm32 GREEN already;
  PVM is blocked on stwo-fork dep-gating + `portable_atomic` (`recursion-p4.md:290-318`).

---

## Grounding appendix (the 2026-06-18 sweep — key anchors)

- **Swap surface:** segment prove `prove.rs:674-928` (Blake2s at `:766,769,928`, SimdBackend
  `:13,760,883,911`); verify `verify.rs:175-374`; proof type `proof.rs:150` + version `:122`;
  object-safe channel `erased.rs:46-50,167` + `framework_access.rs:32-34`; commitment type
  `program_id.rs:39`; standalone verifier `verifier/src/lib.rs:45,70-525`. The Poseidon2-M31
  hasher is CpuBackend-only (`recursion_common/mod.rs:412`); the working round trip is
  `poseidon2_pcs_spike.rs:370-413`.
- **Allowlist:** commitment = `commitments[0]` (`program_id.rs:53-55`); baked
  `VOUCHER_CHECK_COMMITMENTS` (`prover/src/lib.rs:504-519`); `verify_chain_standalone_allowlist`
  (`verifier/src/lib.rs:477-525`); re-bake recipe `prove_transition.rs:847-995`; LIVE path
  `clerk-bridge:736-775` → `verify_chain_segments` (`prover:380-432`).
- **31 components / 530 sites:** `BASE_COMPONENTS` `lib.rs:214-246`; `chip_idx::COUNT=31`
  `lib.rs:210`; OODS re-eval `verify.rs:344` → stwo `core/air/components.rs:54-71`; logup
  relations `lookups/relations.rs`; claimed-sum balance `verify.rs:296-324`.
- **SegmentState:** `proof.rs:126-140`; bound fields pc/ts/registers[13]/memory_root vs
  vestigial `memory_commitment`; io-hash `proof.rs:210-216`; seam `verify.rs:40-47` /
  `verifier/src/lib.rs:418-446`; page-Merkle binding `memory_{page,merkle,root_boundary}.rs` +
  `boundary_binding.rs:116-192`.
- **Cost:** perm chip log 12 = 145s (`recursion-design.md:155`); per-inner-proof ~15.3K perms
  → log 14 (`perm_scale.rs`); join log 15 (2-child) / 16 (next level), ≤ 19 with ~4 bits
  margin (`recursion-p4.md:248-256`). Scalar hasher is the bottleneck; SIMD commit not
  available (grounding §perf.2). Per-join ~5–10 min extrapolated; 7-deep critical path
  ~35 min–1 hr; offline-tractable; memory ~tens of GB/join (uncommitted estimate).
