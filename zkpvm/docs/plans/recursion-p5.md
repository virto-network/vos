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
> **NEXT (precise, grounded):** (a) the row-streaming OODS-embed layout spike
> (cross-row Horner) — the gating decision; (b) bind the streamed embed's `rc` to
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
