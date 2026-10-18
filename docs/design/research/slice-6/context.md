# Slice 6 planning context: masking (M2) and statements on chain (M3)

Gathered 2026-10-18, read-only, on `vos-core` at `31b7938e`.

Path keys:
- `D` = `docs/design/` in the worktree.
- `R` = `D/research/slice-5/`.
- `ST` = `~/src/virto/stwo`, the fork, its checkout on `zk-masking-spike`.
- `SB` = `~/src/virto/stwo-vos-base`, the fork's worktree on `vos/wrap`.
- `P` = `pvm/proof/`.

Every other path is relative to the worktree.

Tags:
- [measured], [model] and [projected] are the docs' own.
- **[est]** is my arithmetic on their numbers, not run.

---

## A. Current state, by area

### A.1 The final proof and its format

**Format 28, the wrap, is admitted and unmasked.**
- Its parameters:
  - blowup 64, 20 queries, PoW 26, interaction PoW 8;
  - fold step 3 and a 2^6 last layer;
  - affine DEEP batching;
  - Blake2b-256 trees and channel.
- Its counts are 146 / 82 (82.60) [model] (`D/proving.md:338-360,545,956`; `P/src/format.rs:394-408`, where `masked: false` is at :408).
- `Format` is at `P/src/format.rs:171-189`. Its fields: `number`, `kind`, `channel`, `encoding`, `params`, `masked`, `floor`, `status`, `reference`, `bits`.
- Its methods: `pcs_config`, `verifier_config` (the batching taken from the format, never from a proof), `interaction_pow_bits`, `meets_floors`.
- Registry functions: `REGISTRY` (:454), `RETIRED` [24,25,26,27,29,31,33,34] (:469), `lookup`, `admitted`, `admitted_segment` (:472-493).
- `WRAP_REFERENCE` is at :269-275.
- The security tool is `P/src/security.rs`: `SecurityShape` (:73), `security_bits` (:111), `proven_bits`, `proven_count`. It has **no masked or (c) terms**.

**Device and credential formats** 37 and 30 are `masked: true` but reserved (`format.rs:421-443`; `D/proving.md:955-957`).

**The fork pin.** `Cargo.toml:174-175` pins `stwo` and `stwo-constraint-framework` to olanod/stwo `ab294189…` (`vos/wrap`). The toolchain is `nightly-2025-07-14` (`rust-toolchain.toml`).
- `vos/wrap` = `vos/base` (`bbfa8bc`) plus five commits:
  - `ad50b6e` the Blake2b-256 hasher and channel;
  - `6bdf07e` fold step 3 reviewed;
  - `225b9bc` affine DEEP batching, opt-in;
  - `ca20894` refuse rather than panic on inconsistent queried values;
  - `ab29418`.
- `vos/base` already holds `8c816ee`, "Sort queries before computing auth paths (#1422)": upstream's fix for spike 2's lifted-Merkle ordering defect (`R/spike2-masking.md:681-709`). It also holds `3aa1309`, a test for a preprocessed tree below the lifting height.
- The divergence log is `SB/.claude/skills/paper-implementation-divergence-log.md`. Its open items:
  - **DIVERGENCE-004:** the composition split, `COMPOSITION_LOG_SPLIT = 1`, is hardcoded at `SB/crates/stwo/src/core/verifier.rs:17,51`;
  - **-011:** the first FRI round folds by `2^fold_step` (about 0.8 bits);
  - **-012:** affine batching counted as `ε_lin(k)`. If wrong, the wrap is at 74.7 proven bits (`P/SECURITY.md` "The Stwo fork's open divergences").

**The wrap prover.** `P/recair/src/wrap.rs`:
- `WrapCircuit` (:59) with `get`, `verify`, `build`, `finalize`, `topology`, `preprocessed_root`;
- `WrapValues` (:67);
- `prove(&Finalized<SecureField>) -> Result<WrapProof, ProveError>` (:200);
- `prove_with(.., tamper)` (:206), which calls `prove_on::<Blake2bMerkleChannel>(&WRAP, ..)`;
- `public_words` (:222).

`prove_on::<MC>(format, circuit, witness, tamper)` (`P/recair/src/prove.rs:188-251`) runs, in order:
1. the header;
2. the preprocessed tree, then main;
3. the 24 outputs mixed;
4. the interaction PoW;
5. `GateRelation::draw`;
6. the claimed sums (:230), then interaction;
7. `stwo::prover::prove` (:243), a stock Stwo call that a masked path must replace.

The pipeline helpers are in `P/recair/src/tree.rs`: `Node`, `leaf` (:56), `fold` (:71), `wrap` (:86).

**The recursion AIR** (`P/recair-air/src/lib.rs`):
- `LOG_CONSTRAINT_EXPANSION = 1` (:43) is a crate constant shared by leaf, fold and wrap.
- All three components finalize with `finalize_logup_in_pairs`: `p2.rs:334`, `qm31.rs:116`, `h8.rs:127`.
- `p2` reads `next_interaction_mask(.., [-1, 0])` (`p2.rs:176`), so a column has at most 2 mask offsets (|O| ≤ 2).
- The circuit hash covers the format number and its parameters (`lib.rs:51-60`).

**Wrap rows:** 16,083 / 21,489 / 2,024, padded to 2^14 / 2^15 / 2^11, with `p2` 98.2% full (`D/recursion-air.md:683-689`).

**Wrap measurements** [measured]. Sources: `D/slice-5-progress.md:3406-3436,4080-4101`; `D/proving.md:372-382`.
- 5.45–6.89 s to prove, at a 2.44–2.5 GiB heap.
- 122,203–125,202 bytes (the window's 123,840).
- On the JAM-only host: 96.3–96.4M gas, of which postcard's decode is 16.0M and the verify 80.3M. The PVM program is 469 KB (494 KB as `vos-statement`'s venue).
- Wasm: 38.3M instructions under the PVF's semantics and 37.8M the client's, about 2.1–2.3 ms. The blob is 292–305 KB.
- 0x400 is not wired.
- **The masked wrap's figures are only [model]:** 117–119M gas and 164–170 KB, both derived from the 85M model (`D/proving.md:366-371`; `D/recursion-air.md:668-671`).

### A.2 The final verifier: `vos-pvm-final-verifier` (`P/final-verifier`)

- **Constants:** `FORMAT = 28` (:66), `PUBLIC_WORDS = 24` (:69), `LAYOUT` (:73), `CONFIG: PcsConfig` (:76-87), `INTERACTION_POW_BITS = 8` (:89), `MAX_PROOF_BYTES = 256 KiB` (:94).
- **Pins:** `LOG_SIZES = [14, 15, 11]` and `PREPROCESSED_ROOT` (`constants.rs:6,10`). A test in `vos-pvm-recair` recomputes both.
- **Types:**
  - `WrapProof { format_version, log_sizes, interaction_pow, claimed_sums: [SecureField; 3], stark_proof }` (:102-109). The claimed sums are published in the clear.
  - `Statement { program: [u32; 8], io_hash }` with `words()` and `from_words()` (:113-140).
  - `Error` with `code()` (:147-215).
- **Functions:** `decode(bytes)` (:218), `verify_bytes(bytes, words)` (:230) and `verify(proof, words)` (:236-283).
- `verify` runs, in order:
  1. `check_header`;
  2. `check_shape`;
  3. canonical claimed sums;
  4. the preprocessed root;
  5. `replay_prefix`, with the interaction PoW;
  6. the logup total with the public terms;
  7. `check_samples`;
  8. `stwo::core::verifier::verify` (:280).
- **The crate is single-format.** No dispatch exists.
- **Dependencies:** `stwo` (no default features), `vos-pvm-recair-air`, `num-traits`, `serde`, `postcard` (`P/final-verifier/Cargo.toml`).
- **Builds:** no_std, and stable for x86 and wasm32. The Wasm harness is `P/final-verifier/wasm/{blob,run}`.

### A.3 The statement and the venue: `vos-statement` (`P/statement`)

- **Types:**
  - `ProgramId([u32; 8])` (`lib.rs:100-112`);
  - `SpaceId([u8; 32])`, with `SpaceId::NONE` (:116-122);
  - `RootRead { kind: u8, space, window: u64, root: [u8; 32] }` (:126-131). **`kind` is a raw byte with no registry or enum.**
  - `StatementId` (:153).
- `Statement { format: u32, program, space, public_args, output, roots }` (:157-171) has these methods:
  - `encode` and `decode`, SCALE and canonical (:175-226);
  - `io_hash() = BLAKE2b-256("vos/io/v1" ‖ args ‖ output ‖ roots)` (:231-235);
  - `id() = BLAKE2b-256("vos/statement/v1" ‖ program ‖ space ‖ io_hash)`, without the format (:240-251).
- **`trait Venue { accepts(format), anchored(&RootRead), seen(&StatementId) }`** (:271-278).
- **`enum Refusal { Statement, Format, Program, Space, Unanchored, Repeated, Proof }`**, with `code()` giving 1–6 or `0x100 | err` (:282-316). `code(verdict)` is at :336.
- **`admit(venue, program, statement) -> Admitted { id, words }`** (:367-403) checks, in order:
  1. `statement.format != FORMAT` (single-format: 28 only, :372);
  2. the program equals the venue's pin;
  3. the space rule: rootless means `NONE`, otherwise every root's space is the statement's;
  4. every root anchored, via `venue.anchored`, with **no notion of a carried or unanchored root kind**;
  5. the io-hash and the id;
  6. `seen`.
- `Admitted::verify(proof)` (:351) and `judge = admit` then `verify` (:413-420).
- **`model`:** `Policy { formats, anchors, seen }`, `Input { program, policy, statement }`, `judge_bytes` (`model.rs:19-114`). The `fixtures` feature is std.
- **The JAM venue** is `src/bin/final-verify.rs`, `final-verify.elf`:
  - payload mode 0 verifies the words, mode 1 judges an `Input`;
  - the proof comes as a preimage via `historical_lookup`, at most 256 KiB, after admission;
  - the pin and the venue's state come in the payload for the harness only (:1-27). There is no accumulate and no stored state.
- **Dependencies:** `vos-pvm-final-verifier` and `blake2 0.10` (no default features). It "depends on nothing of VOS beyond the final verifier, so Kreivo can depend on it" (`lib.rs:56-57`; `Cargo.toml`).

### A.4 Fixtures

- `P/fixtures`:
  - `wrap.proof` (124,025 bytes), `wrap-prefix.proof`, `wrap-midway.proof`;
  - `statements.cases` (13 cases, 6.4 KB);
  - segment fixtures for 35 and 36.
- The table of verdicts is `D/proving.md:1020-1060`.
- **The generator** is `P/tests/kernel/fixtures.rs`. It is deterministic: the stale test regenerates the fixtures and compares them byte for byte, under both feature sets (`D/slice-5-progress.md:3546-3548,3787`).
- The transition case "the same run, another accepted format" uses 38, "a number no format holds", recorded as already seen. The direction "28 then the successor" waits for the masked format (`D/proving.md:1043-1051`).
- **Judged alike** at four venues: native, Wasm under the PVF's and the client's semantics (`just judge-wasm`), and the JAM-only host.
- **Fuzzing:** three targets (`final_verifier_bytes`, `final_verifier_mutate`, `statement_decode`), 10–25 minutes each, run by hand, not in CI (`D/slice-5-progress.md:3594-3609,3690-3716`).

### A.5 The JAM agent today

- **JAM mode (slice 4):**
  - the default agent's refine runs a batch over a witness and applies the result;
  - accumulate swaps the root, with time and skew checks, and records exports;
  - "it verifies nothing else: the builder is trusted … until proofs" (`D/core-model.md:1048-1115`; `D/slice-4-jam.md:619-725`; `D/slice-4-progress.md:729-913`).
- A PolkaJam 0.1.29 testnet milestone ran on the interpreter backend. Refines took 0.26–41M gas [measured].
- **No statement-verifying JAM service or agent exists.** The only verifier on JAM is the `final-verify.elf` harness program above.
- **Limits that bind an actor-hosted verifier:**
  - `MAX_HANDLER_GAS = 100_000_000` (`agent/wire/src/defaults.rs:32`), against a measured 96M verify unmasked and about 130M masked [est];
  - JAM's `Limits`: `program: 512 KiB` against `final-verify.elf`'s 494 KB alone; `message` and `attest` at 2 KiB; 8 messages and 8 attests (`agent/wire/src/abi/cap.rs:234-249`);
  - `historical_lookup` is used only by the default agent for program blobs (`agent/default/src/machines.rs:103,163`). Actors have no preimage access.
- Messages between agents on JAM are unbuilt (`D/core-model.md:1092-1094`).

### A.6 `#[attestable]`, `&self` and the public-input model

- **`#[attestable]` forbids `self`:** "an #[attestable] method takes no `self`: it sees only its arguments" (`agent/sdk-macros/src/messages.rs:119-130`). It takes no role or `linearizable` and no context, and cannot fail (:110-117,181,197-202).
- **The generated entry** is `__vos_attest_<name>(arguments, len, io_hash)`, which decodes, calls, and calls `runtime::attested` (`messages.rs:389-436`).
- **The SDK's io-hash** is `compute_io_hash(&[], &output, &[])` (`agent/sdk/src/runtime.rs:112-117`). Every attestable statement today is rootless with empty `public_args`.
- `#[public]` does not exist in the macros.
- **`Attest { program: ProgramHash, witness_input: Vec<u8>, output }`** (`agent/wire/src/result.rs:348-360`) has no window and no proof hash.
- **Attest arguments are capped** by `Limits::attest`: `REQUEST = 64 KiB` on VOS and 2 KiB on JAM, enforced at `agent/default/src/refine/invocation.rs:491`. Also `ATTESTS = 16` a step (`cap.rs:9,27,195-196`).
- **The window kernel** is `agent/test-actors/window/src/lib.rs`:
  - `state(&mut self, ctx, space, window_i, root_i, window_j, root_j, rows, proof_i, proof_j)` with `#[msg(gas = 100_000_000)]` (:66-95) calls `ctx.attest(window::Settle{..})`;
  - `#[attestable] settle(..)` (:100-128) receives the **map roots and the multiproofs as arguments**;
  - its statement is rootless, with `public_args` empty; its space and anchors are in its output (`D/proving.md:443-448`).

### A.7 The prover worker

- **None exists.** No crate under `agent/` or `node/` depends on `vos-pvm-proof`, `vos-pvm-recair` or `vos-statement`. The only dependants are `pvm/*`, the spikes and `pvm/bench`.
- Proofs are made only in tests: `test-proof`'s `the_window_wraps` and `the_predicate_wraps`.
- `Attest` records live in work results in the agent's log (`result.rs:345-347`).
- **Program ids** are computed only in tests. "Nothing outside the tests pins an id today" (`D/slice-5-progress.md:4196-4200`).
- **Measured end to end** (`D/slice-5-progress.md:4035-4078`):
  - the window statement: 26 segments, 324 s, segments at a 4.79 GiB heap, a 9.2 GiB process peak;
  - the predicate: 38 s;
  - `kernel` tests run one at a time at 16 GiB.

### A.8 Roots, anchors, windows and `SpaceId`

- **Per-map roots only.** `node/host/src/roots/mod.rs:135` gives `root(snapshot, agent, map) -> (Hash, version)`, and refuses with `Building` mid-build. A map root is at a state version, not a window.
- **What is missing from code:**
  - agent roots (VOS), space roots, window cuts and anchors;
  - **any `SpaceId` type in `agent/` or `node/`** (grep: none).
- `D/core-model.md:709-710` says "No global state root on VOS. Agents deployed on JAM keep one."
- **Designs only:**
  - `D/proving.md:677-698` (§7);
  - `D/identity-and-authority.md:402-434` (§11);
  - `R/kreivo-pallet.md:189-211`;
  - `D/slice-6-clerk.md:174-198`.

---

## B. The slice-6 work inventory

Sources:
- the owner's M2 and M3 rows (`D/proving.md:809-810`);
- "To slice 6" (`D/slice-5-progress.md:4163-4224`);
- the external audit (:4226-4247);
- the code-quality rest (:4155-4161).

For each item: **Decided**, **Open**, **Depends on** (Dep), **Evidence** (Ev).

### M2 Masking (the wrap only)

**M2.1 Bring the prototype to the pin.**
- **Decided:** variant (c), with R1–R8, masking in our fork's public API, not upstream (`R/spike2-masking.md:105-123,994-1016`; `R/masking-review.md:381-410`; `D/proving.md:601-622`).
- **What exists:**
  - `ST` branch `zk-masking-spike`: `539f419`, `c9835e2`, `661267a`, `92ecb7e`, `ec451ad`, based on `4f417dd`;
  - **local only:** origin's heads are `dev`, `no-std-pvf-gating`, `vos-verifier`, `vos/base` and `vos/wrap`;
  - additions only: `crates/examples/src/zk_masking/{mod.rs 792 lines, tests.rs 1,283}` and `examples/zk_masking_bench.rs`;
  - API: `ZkParams` (:77-112, with `salt_columns: 4`), `MaskLayout`, `mask_trace`, `commit_salted`, `ExpandedEval`, `MaskedComponent`, `prove_zk`/`prove_zk_ex` (:457-472), `verify_zk` (:568-630), `revealed_functionals_independent` (R1), `rank_m31`.
- **Open:** its home.
  - In vos-core: `recair` for the prover, `final-verifier` for the verifier.
  - In the fork as a no_std core module.
  - **`verify_zk` is std example code with its own flow:** it commits the composition as 4 + 4 mask + salt columns. It cannot reuse `stwo::core::verifier::verify`, whose split is hardcoded (DIVERGENCE-004).
- **Dep:** none. **Ev:** the prototype's 15 tests on wide Fibonacci and plonk [measured].

**M2.2 A wrap-only AIR variant.**
- Under (c), the constraint bound is `log_size + 2` (`LOG_CONSTRAINT_EXPANSION = 2`).
- R2 adds 4 blinding main columns per component and a blinding relation id used by nothing else.
- **Must not move format 32:** `LOG_CONSTRAINT_EXPANSION` is a crate constant today (`recair-air/src/lib.rs:43`). Adding columns to the shared components would change every leaf and fold proof, `H_fold`, every leaf-circuit hash and every program id.
- **Dep:** M2.1. **Ev:** none yet. The stale-fixture test is the guard.

**M2.3 The masked prover pipeline**, replacing `stwo::prover::prove` at `recair/src/prove.rs:243` for the masked format:
- mask the main and interaction columns as `f + v_H·r`, with `h ≥ 2(4|O| + q(|O|+1))` and |O| ≤ 2 (256 at about 24 queries [est], ≤ N/4 = 512 at `h8`'s 2^11);
- salt the main, interaction and composition trees with **8 M31 columns each, 248 bits** (`D/proving.md:580`; `R/critique.md:107-111`). The prototype used 4;
- commit the composition whole at 4N, with lifting at m+2;
- add the FRI mask `R` (4 columns), committed before the DEEP coefficients;
- blind the claimed sums (R2). The wrap's public sum is only the 24 words plus `u` (`final-verifier/src/lib.rs:271-272`, `LAYOUT.public_terms`), so **the boundary re-cut part of R2 is trivial for the wrap**: no private boundary value is public;
- R1, the rank check with re-randomize and retry;
- R3, the FRI-mask rank test. Under affine batching the condition is per-coefficient, not γ's powers: re-derive it;
- R4, hedged randomness `H(OS ‖ witness digest)`.
- **Dep:** M2.2, M2.4. **Ev:**
  - R1 built and measured at 0.9–17 ms a column class (`R/spike2-masking.md:802-843`);
  - R2, R3 and R4 argued, not built (`:1032-1035`).

**M2.4 The masked format entry.**
- **A new number.** A.4's rule: "a number names one AIR and one set of parameters" (`D/proving.md:982-986`). A.4 also allows "a bump of 28" (:980-981), which the rule rules out.
- `masked: true`.
- R6 pins: `h`, the salt and mask columns, the AIR level m, the composition point `π(z)`, the per-class `log_sizes`.
- **Parameters are open.** (c) trades one blowup bit: FRI at blowup 32 needs about 23–24 queries for ≥ 80 proven bits with affine batching [est]. The alternative keeps FRI at 64, with commitment memory ×2.
- **The security tool must gain (c)'s terms** (`R/spike2-masking.md:776-800`):
  - the composition bound 4N;
  - the DEEP point uniform on half the circle;
  - the masked trace bound 2N.
- **Dep:** none; first. **Ev:** none for the masked shape.

**M2.5 The masked final verifier**, in `final-verifier` beside 28 or replacing it in production:
- **no_std and panic-free:** extend `check_shape`/`check_samples` to the salted trees and mask columns, since the prototype "can still panic inside `verify_values` on a tree-width mismatch" (`R/spike2-masking.md:935-940`);
- new `PREPROCESSED_ROOT` and `LOG_SIZES`;
- **a multi-format dispatch:** `FORMAT` and `admit`'s `format != FORMAT` are single-valued today;
- **the fixed-layout decode:** postcard is 16.0M of the 96.4M gas, and a fixed layout also makes the bytes canonical;
- **the Blake2b hook:** VOS's `0x400` is a compression call (`D/core-model.md:916-943`). Kreivo serves only the whole-message `sp_io::hashing::blake2_256` (`R/spike4a-final-gas.md:270-279`). So the hook belongs at message level, with a compression-based implementation for the PVM.
- **Dep:** M2.3, M2.4.
- **Ev:**
  - 0x400 is ×0.79 [model] (`R/spike4a-final-gas.md:250-269`); the host `blake2_256` −24–36% Wasm instructions [measured on the proxy];
  - **JAM itself serves no hash** (`:259-264`), so 0x400 helps only VOS hosts.

**M2.6 `vos-statement` at the masked format.**
- `FORMAT` becomes an accepted set dispatched to the verifier.
- Regenerate the fixtures.
- Add the transition case in both directions.
- Add adversarial "replay with this field changed" cases per id and io-hash field: space, format, venue, window, nonce (`D/slice-5-progress.md:4190-4192`).
- **Masked proofs are randomized:** the byte-for-byte stale-fixture test (A.4) breaks unless the RNG is injectable in tests only.
- **Dep:** M2.5.

**M2.7 Gates** (`R/spike2-masking.md:876-985`, amended at `R/masking-review.md:411-428`):
- soundness 1–10 masked:
  - the degree audit (≤ 3; recair-air is degree ≤ 3 with paired logup [measured], `D/proving.md:124-125`);
  - tamper per masked field;
  - the blinding soundness gate;
  - structure errors, never panics;
  - both bit counts;
- leakage 1–7:
  - rank tests, R3 included;
  - a simulator;
  - witness-pair χ²;
  - hidden states, by a byte search over **every carrier**;
  - fresh and replayed-RNG randomness;
  - the claimed-sum control;
  - the shape class public;
- the budget gate: ≤ 24 GiB and ≤ 200M gas (`D/proving.md:799`; `D/recursion-air.md:828`).
- **Ev:**
  - the projections give 132–135M gas in software and 150–174 KB [est: 96.4M and 124 KB × the toy's 1.37–1.40, or the proxy's ×1.21];
  - 3.8–4.3 GiB heap and 9–12 s to prove [est: 2.5 GiB and 5.45–6.89 s × 1.56–1.70].

**M2.8 The carrier audit (R7).**
- **What may leave** is only the `Statement` and the final proof (A.5, `D/proving.md:988-1002`).
- **What to audit:**
  - `Attest` and work results;
  - `RefinePayload` (`P/src/refine/encode.rs`);
  - the JAM anchor chain, blobs and logs;
  - the tests' `target/tmp/wrap/` writes;
  - `CPU_DUMP` and other env debug output (quality review item 21).
- **Dep:** M3.4, to know the worker's carriers.

**M2.9 Device proofs: what slice 6 must and need not do.**
- **Must:**
  - build the masking generic over the component set and `MerkleChannel`, since the credential AIR is recair's `p2` (`D/proving.md:702-714`) and devices use Blake2s-M31;
  - keep the R1 and R3 checks generic;
  - give the security tool (c) for any shape.
- **Cheap and worth doing:** the static ≤ 3 degree audit (R5) over the 25 segment chips, which retires slice 7's (c) premise early.
- **Need not:**
  - admit 37 or 30;
  - re-cut the segment boundary binding (Fable's table per boundary chip, `R/masking-review.md:193-205`);
  - drop the segment states from the format;
  - the masked 2^11 floor;
  - phone runs.
- `D/proving.md:809`'s "R1–R8 … on device proofs" is stale against the owner's narrowing (see E.1).

### M3 Statements on chain

**M3.1 The public-input model** (a design round, Fable).
- **Decided:**
  - the `Statement` shape, the io-hash, the id without the format, the rootless rule;
  - the venue's pin is never the caller's (`D/proving.md:389-501`; 5.15b, 5.16a).
- **Open:**
  - `#[public]` arguments in the SDK and the io-hash (none today, A.6);
  - roots in the io-hash (from `&self` reads);
  - **`RootRead.kind` semantics:** a registry or enum (Kreivo's sketch is `SpaceWindow = 0, Carried = 1`, `R/kreivo-pallet.md:105`). Today `judge` requires every root anchored, so **a Clerk statement spanning from an older settled anchor fails `Unanchored` once the venue prunes it**. Either a carried kind the handler checks (`R/kreivo-pallet.md:200-204`), or anchors kept per pair;
  - **F2, the venue binding** (`D/slice-5-progress.md:4174-4183`): a venue domain in the io-hash or id, or in-code migration ranges. Rootless statements need it through `public_args`;
  - `Attest` gains the window, then the final proof's hash (`D/proving.md:998`);
  - the low-entropy rule (`:466-468`), enforced or documented;
  - **whether production venues accept 28 at all:** §1 and A.5 say only masked proofs leave.
- **Dep:** none; it gates M3.3 and M3.5.

**M3.2 `SpaceId`, windows, agent and space roots, anchors.**
- **Decided on the evidence, the owner's to override:**
  - reads at the last anchored cut, to the space root (`D/proving.md:844`);
  - the space root commits `(space_id, window)` (:688-689).
- **Open:**
  - the `SpaceId` derivation (the creation record's hash, `D/slice-6-clerk.md:147-148`);
  - the window clock: relay blocks / `WindowLength` on Kreivo (`R/kreivo-pallet.md:198-199`) against JAM time (`D/slice-6-clerk.md:183-185`);
  - **Kreivo's window length**, deferred to slice 6 (`D/proving.md:686-687,851`);
  - who builds the space root over independently replicated agents (the representative agent, `D/identity-and-authority.md:409-412`);
  - a deterministic per-agent cut;
  - the host-independent root kind: JAM's agent root is the whole-keyspace tree, VOS has none (`D/proving.md:693-696`);
  - who signs anchors (the node ed25519 keys, `R/kreivo-pallet.md:180-185`).
- **Dep:** M3.1. **Ev:** none in code (A.8).

**M3.3 `&self` attestable reads.**
- Witnessed rows plus `BatchProof`s, then map root → agent root → space root, at the anchored cut.
- The macro lifts its "no self" rule (`messages.rs:119-130`).
- The agent serves the witness.
- The kernel states its roots in the io-hash.
- The window kernel is restated (its roots out of the arguments, its anchors out of the output).
- **Open:** whether the witness counts against `Limits::attest`, 64 KiB on VOS and 2 KiB on JAM (`invocation.rs:491`). `D/proving.md:196` assumes 4 MiB.
- **Dep:** M3.1, M3.2. **Ev:** "a few dozen more compressions" [unquantified] (`D/proving.md:679-682`).

**M3.4 The prover worker**, a node extension in the space's trust domain (`D/core-model.md:902-904,1434-1442`). It:
- takes `Attest` records at anchored windows;
- re-runs each kernel;
- proves segments, leaves, folds and the masked wrap;
- keeps everything below the wrap inside the role;
- publishes the `Statement` and the proof, the proof as a blob (CAS);
- submits to the venues;
- is idempotent by statement id;
- carries the reproducibility gate: the program ids, `H_fold` and the wrap root as repository constants, checked under both feature sets and on aarch64, plus a `program-id` tool (`D/slice-5-progress.md:4196-4200`).

The program id needs the install's `Derivation` plus the recursion stack (`D/proving.md:486-497`).
- **Dep:** M2 (the masked wrap), M3.3.
- **Ev:**
  - the window takes 324 s and a 9.2 GiB process peak [measured];
  - masking adds a few seconds [est];
  - throughput against the window cadence is unknown.

**M3.5 The Kreivo pallet** (`R/kreivo-pallet.md`; `D/proving.md:626-671`). Staging is in `R/kreivo-pallet.md:321-324`.
- **P0:**
  - the registries: formats; programs with a delay; spaces with a controller and anchor keys; the anchor table keyed by kind too;
  - `anchor` and equivocation handling;
  - `RejectVerifier` and the `Record` handler;
  - pauses, pruning, the length cap, tests.
- **P1:** the real verifier through `vos_statement::judge`, FRAME weights benchmarked on the reference machine, the dependency path and the home.
- **Decided:** after the recursion, P0 and P1 together; the check order; fail-closed; panic-free; the words an input; every re-pin a governance event.
- **Open:**
  - its home, frame-contrib "to be confirmed";
  - governance origins and delays (`R/kreivo-pallet.md:311-312`), fees, anonymous submitters;
  - **the `Credential` handler:** `D/proving.md:668-670` lists it as built in, while P0 has `Record` only.
- **Dep:** P0 on M3.1 and M3.2 only, so it can run early; P1 on M2.5 and M2.6.
- **Ev:**
  - masked Wasm about 46–54M instructions, or 32–41M with `blake2_256` [est];
  - ref_time about 4e9–7e9 ps at 0.125 ns an instruction [projected], against 1.5 s normal-class weight;
  - length: about 22–26 proofs a block in the 3,932,160-byte normal class [est];
  - Kreivo's limits [read]: 2 s ref_time, 5 MiB PoV, a 3 MiB code cap (`R/spike4a-final-gas.md:353-362`; `R/kreivo-pallet.md:27-31,88-96`).

**M3.6 The JAM verifier agent.**
- **Decided:** refine verifies, accumulate records; accepted program ids are constants changed by redeploy; payloads arrive as preimages (`D/proving.md:672-675`).
- **Open:**
  - a dedicated service (`final-verify.elf`'s refine plus a new accumulate), or an actor in the default agent, which A.5's limits block;
  - anchors and the seen set live in state that refine cannot read, so `admit` splits between accumulate and refine.
- **Dep:** M2.5, M3.1.
- **Ev:** 96.4M gas unmasked, about 132–135M masked in software [est], against PolkaJam's 1e9 refine.

### Carried (`D/slice-5-progress.md:4163-4224`)

- **C1.** Forgery gates for the recursion AIR, the hardening's standard:
  - `p2`'s modes and chaining;
  - `Gate`'s signed multiplicities (R12);
  - `assert_one_of`;
  - the lane gadgets;
  - the leaf's unchecked boundary bytes.

  Invariant: an unread lane is not zero. No dependency; parallel.
- **C2.** Panic-freedom by construction:
  - the fuzz campaigns as a CI job;
  - an audit of every index and `unwrap` on the verify path at the pin, for the masked path too.

  Dep: M2.5.
- **C3.** The reproducibility gate (in M3.4).
- **C4.** Kreivo's dependency path:
  - the chain: `vos-statement` → `vos-pvm-final-verifier` → `vos-pvm-recair-air` → `vos-pvm-poseidon2` and the git-pinned Stwo fork;
  - Kreivo already takes frame-contrib by git (`~/src/virto/kreivo/Cargo.toml:60-68`), so a git pin is the established pattern;
  - only publishing to crates.io would force vendoring (frame-contrib's publish policy: to check).
- **C5.** Format 36 retired, or the refine path moved to 35.
  - 36 is still `PROOF_FORMAT_VERSION` (`P/src/proof.rs:35`), the default `prove` (`P/src/prove.rs:190`) and the refine codec's.
  - It stands at 96 / 57.
- **C6.** Format 32 stays reserved. Nothing to do.
- **C7.** Prover-time levers, open:
  - the ALU chips pad to the class's steps;
  - WITNESS_INPUT pads to 2^16 per segment;
  - a leaf over several small segments;
  - A.7's 8 s at load.
- **C8.** Recorded and unfixed:
  - C-DJUMP;
  - the ledgers' 2^27-step gap;
  - a BLAKE2b pointer within 256 bytes of 2^32;
  - refine slices' page permissions.
- **C9.** The external audit: its scope at `:4228-4245`; its owner and timing are open.
- **C10. The code-quality rest.** `D/slice-5-progress.md:4155-4161` assigns it to "the cleanup before master". The owner put it in slice 6 (decision 13). Items from `research/slice-5/quality-review.md` not taken in 5.16b–c:
  - the compiler's `shape::chip` (item 13's rest);
  - the interaction-side row view;
  - item 11, `record_step` (not behaviour-preserving on invalid traces);
  - items 14, 15, 18, 19, 20, 21, 23, 24, 25, 26, 33, 34, 35;
  - the two removals not taken: the relabel seam for formats 18/19, and merging the fuzz target's Grow/Shrink/Clear.

  Verify each against 5.16b–c's commits first (`D/slice-5-progress.md:3882-3956`).
- **For the owner:** AVX-512F is compiled but never run; PolkaJam's recompiler needs a machine whose cores report L3.

**Estimates:** M2 6–8 weeks and M3 8–12 weeks (`D/proving.md:809-810`). M3's row does not itemize `SpaceId`, the space root, the window clock or anchors (M3.2), which `D/slice-6-clerk.md` sized as their own design rounds.

---

## C. Feasibility risks, with the evidence that retires each

Ordered by how much of the plan rests on the risk.

1. **(c) on the real wrap is untested.**
   - **The prototype ran:** a 100-column wide-Fibonacci and a plonk component; Blake2s; fold step 1; DEEP batching by powers; on `4f417dd`.
   - **The wrap differs:**
     - three components at 2^11 to 2^15 with paired logup;
     - affine DEEP batching (DIVERGENCE-012);
     - fold step 3 (-011);
     - the Blake2b channel;
     - blowup 64.
   - **The cost factors** (×1.6 prover, ×1.37–1.40 proof and verify) come from the toy. Spike 4a's structural proxy says ×1.21 (`R/spike4a-final-gas.md:408-434`).
   - (c)'s prover factor "depends on how much of a window's time is constraint evaluation … not measured" (`R/spike2-masking.md:755-756`).
   - **Retire:** a spike that rebases the examples-only prototype onto `vos/wrap` and masks the real wrap circuit under (c). Measure time, heap, bytes and verify gas, and run R1 on it. Days; no format work needed. **Do this before fixing M2's step list.**
2. **The security count for the masked format.**
   - `security.rs` has no (c) terms: the 4N composition, the half-circle DEEP point, FRI at B−1.
   - The query count that keeps ≥ 80 proven bits at blowup 32 under affine batching is uncomputed (about 23–24 [est]).
   - -012's citation is unreviewed. If it falls, the masked wrap needs blowup 8 and 41 queries, or a batching-phase PoW (`D/proving.md:346-352`).
   - **Retire:** extend the tool, pin candidate shapes, and get Fable's check of the terms (days).
3. **No reusable masked verifier.**
   - Stwo's `core::verifier::verify` hardcodes the composition split (DIVERGENCE-004, `SB/crates/stwo/src/core/verifier.rs:17,51`).
   - The prototype's `verify_zk` is std example code with known panics.
   - A no_std, panic-free masked verify path is new soundness-critical code: Fable, fuzzing, the audit's scope.
   - **Retire:** write it inside `final-verifier` over `CommitmentSchemeVerifier::{commit, verify_values}` and the components' public API, as the spike showed is possible (`R/spike2-masking.md:854-866`). Fuzz it with the existing targets.
4. **Masking moving format 32 by accident:** the shared `LOG_CONSTRAINT_EXPANSION`, or blinding columns in the shared components.
   - **Retire:** make both per-format. The stale-fixture test, the program ids and `H_fold` must stay byte-identical (already a test).
5. **R2, R3 and R4 are unbuilt; the zero-knowledge argument is conditional.**
   - It holds in the programmable random-oracle model, given R1 on every proof (`R/masking-review.md:21-27,80-98`).
   - Leakage tests are statistical evidence.
   - **Retire:** build each with its gate, and add a Fable review of the masked transcript.
6. **Randomized proofs against deterministic fixtures and the reproducibility gate.**
   - The fixture generator's byte-for-byte stale test (`D/slice-5-progress.md:3546-3548`) cannot hold for masked proofs.
   - **Retire:** a test-only RNG seam that no production build can enable, with a leakage test asserting OS entropy in release. Otherwise fixtures are judged by verdict, not bytes. The preprocessed root and the constants stay deterministic.
7. **Space and agent roots, windows and `SpaceId` do not exist** (A.8). `D/core-model.md:709` says VOS has no global root.
   - A deterministic cut across independently replicated agents, and the representative's aggregation, are new protocol surface.
   - So is the host-independent root kind (`D/proving.md:693-696`).
   - This is the largest schedule risk in M3, and §11's 8–12 weeks does not list it.
   - **Retire:** a design round and a Fable review first. Then a single-agent space root (one agent, root = H(space_id ‖ window ‖ agent roots)) proved end to end before multi-agent.
8. **Witness size.**
   - Attest arguments, which are the witness input, are capped at 64 KiB on VOS and 2 KiB on JAM (`cap.rs:9,195-196,239-240`; `invocation.rs:491`).
   - `D/proving.md:196` says 4 MiB.
   - The window kernel already passes rows and two multiproofs as arguments, and paths to the space root add more.
   - **Retire:** measure the window kernel's argument bytes per row today, and decide whether served witnesses count against `attest`. Cheap.
9. **The JAM verifier as an actor does not fit:**
   - `MAX_HANDLER_GAS` is 100M (`defaults.rs:32`) against 96M unmasked and about 130M masked;
   - JAM's program cap is 512 KiB against a 494 KB verifier;
   - JAM messages and attests are 2 KiB;
   - actors have no preimage access.
   - **Retire:** decide on a dedicated service, which the evidence favours. Prototype its accumulate on the JAM-only host (`P/statement/tests/support/jam.rs` exists), then a PolkaJam testnet run.
   - Refine cannot read state, so the anchored and seen checks move to accumulate, after the expensive verify.
10. **Kreivo integration.**
    - **Never built inside a real runtime:**
      - `wasm32v1-none` through substrate-wasm-builder, on Kreivo's stable toolchain and stable2603 lockfile;
      - dependency unification (`blake2 0.10`, `serde`/`postcard` no_std, `num-traits`, the git-pinned `stwo` at no default features);
      - code size against the 3 MiB cap.
    - The weight is a projection: 0.125 ns an instruction on a Xeon 8370C.
    - **Retire:** a throwaway Kreivo branch that links `vos-statement`, builds the runtime Wasm, and runs a FRAME benchmark of `judge` on the golden fixtures (1–3 days). Modesto's precedent: a 0.264 MiB compressed verifier, stwo's `poseidon252` gate (`R/kreivo-pallet.md:46-77`), already in the pin (`4f417dd` ⊂ `vos/base`).
11. **Panic-freedom on the masked path.**
    - A FRAME runtime aborts the block's import on a panic (`D/proving.md:649-658`).
    - Fuzzing runs by hand today.
    - **Retire:** C2, plus `check_shape` covering every masked tree.
12. **Prover worker throughput against cadence.**
    - One window statement is 5.4 minutes at about 9 GiB, one at a time [measured].
    - The window cadence is "minutes" (`D/identity-and-authority.md:411-413`).
    - With several kernels or spaces a node may lag.
    - **Retire:** compute from the measured rows once the window length is chosen, and set the cadence at or above the proving latency, or provision provers.
13. **Every wrap change re-pins at every venue:** a Kreivo runtime upgrade on Root's 4-day track (`R/kreivo-pallet.md:248`), a JAM redeploy. Masking changes only the wrap's constants, not program ids or `H_fold` (it touches no leaf or fold), if M2.2 holds. Plan few masked-format iterations.
14. **(c) mechanics already retired, still to pin by test on the wrap's shape:**
    - the lifted-Merkle ordering defect (fixed in the pin, `8c816ee`);
    - "lifted protocol and degree ≥ 2" (`R/critique.md:338`): the prototype's (c) tests pass;
    - the composition evaluation mode re-LDE (`R/critique.md:280-284`): a uniform +2 is at most `log_blowup` 5, so no re-LDE.
    - **Retire:** one test each on the masked wrap.

---

## D. Decisions: the owner's, and those the evidence settles

**The owner's** (options and evidence):
1. **F2, the venue binding:**
   - (a) an SDK-mandated venue field in the io-hash preimage (`vos/io/v2`, changes every kernel's code and id);
   - (b) a convention in `public_args`, by audit;
   - (c) in-code migration ranges, rooted statements only.

   Rootless statements need (a) or (b) (`D/slice-5-progress.md:4174-4183`; `P/SECURITY.md:184-189`).
2. **The window clock and Kreivo's window length** (`D/proving.md:686-687,851`). Options: relay block / `WindowLength`, JAM slots, or per-pair sequence cuts for the Clerk (`D/slice-6-clerk.md:176-181`). Bounded below by the prover's latency (C.12).
3. **`SpaceId` and the space root's builder:** the representative agent (identity §11), and which keys sign anchors.
4. **Where anchors and registries live first:** the Kreivo pallet (`D/proving.md:626-671`), or the JAM registry agent (`D/identity-and-authority.md:402-463`). One anchor venue per space at a time (`D/proving.md:690-692`).
5. **The JAM verifier's shape:** a dedicated service (the evidence: C.9) or an actor in the default agent (which needs `MAX_HANDLER_GAS`, program-cap and preimage changes).
6. **The pallet's home** (frame-contrib or Kreivo) and the dependency path, git pin or published (`D/proving.md:671,851`).
7. **Program governance** (origin, delay, emergency track), fees per proof, anonymous submitters (`R/kreivo-pallet.md:300-324` recommends).
8. **Whether the `Credential` handler is in P0/P1** or waits for slice 7's credential AIR.
9. **Format 36:** retire it, or move the refine bundles to 35.
10. **The external audit's** owner and timing.
11. **The code-quality rest's** placement: slice 6 or the cleanup before master (`D/slice-5-progress.md:4157`).
12. **`RootRead` kinds for spans:** a `Carried` kind checked by the handler, against anchors kept per pair (affects the Clerk; A.3, M3.1).

**Settled by the evidence** (the owner's to override):
- **A new format number for the masked wrap.** A.4's rule rules out "bump 28"; 38 is used in a fixture as "no format holds".
- **Production venues accept masked final formats only.** 28 stays a test format, by §1 and A.5 (`D/proving.md:33-36,988-990`; `R/kreivo-pallet.md:258-259`). The "both directions" transition case is then between masked formats, or test-policy only.
- **Column-form salts,** not salts inside `MerkleHasherLifted`, which is a SECURITY-CRITICAL fork file (`R/masking-review.md:115-119`); 8 M31 each (248 bits).
- **(c), not (a) with unpairing.** The recursion AIR is degree ≤ 3 with paired logup, so no unpairing is needed (R8's comparison is moot for the wrap).
- **The masked FRI parameters:** the cheapest shape the extended tool counts at ≥ 100 / ≥ 80. Likely B−1 = 5 with about 23–24 queries [est].
- **The R2 boundary re-cut is trivial for the wrap:** its public terms are the words and `u` only.
- **The masking code lives** in vos-core's `recair` and `final-verifier`, over the fork's public API; the fork is untouched or gets additive commits only, pushed after a Fable review.
- **The Blake2b hook at message level,** with a compression-based PVM implementation.
- **The fixed-layout decode** in the masked format.
- **The statement's shape stays as built:** the id without the format, `ProgramId` as 8 M31, no `shape_class`. Kreivo's sketch is stale (E.6).

---

## E. Inconsistencies and stale statements

1. **`D/proving.md:809`** (§11 M2, "R1–R8 on the wrap and on device proofs") and **:603** (§5, "Where: device proofs, and the final wrap") predate the owner's narrowing to the wrap. **:799** and **`D/recursion-air.md:828`**: fine.
2. **`D/proving.md:196`** caps the witness input at 4 MiB. The code caps attest arguments, the witness input, at 64 KiB VOS / 2 KiB JAM (`cap.rs:9,195,239-240`; `invocation.rs:491`). **`D/slice-6-clerk.md:59,209`** assumes the witness channel lifts the 64 KiB cap. It does not.
3. **Masked-cost figures rest on the 85M model, not the measured 96.4M:**
   - `D/proving.md:366-371` and `D/recursion-air.md:668-671`: 117–119M, 164–170 KB;
   - measured × (c) gives about 132–135M in software [est].
   - `D/recursion-air.md:668` also says "3.5–7.8 GiB" against a measured 2.5 GiB base.
4. **`D/proving.md:1050-1051`** (A.6: "slice 6's masked format adds the case the other way round", 28 then masked) against §1 and A.5: production venues should never accept 28.
5. **`D/proving.md:396`:** `public_args` is "the kernel's #[public] arguments". No `#[public]` exists, and the SDK hashes empty args and roots (`agent/sdk/src/runtime.rs:113`).
6. **`R/kreivo-pallet.md` against what was built:**
   - its `Statement` has `program_id: [u8;32]`, `format: u16` and `shape_class` (:107-113);
   - its id hashes the format and `shape_class` (:148), where the built id is without the format (5.16a);
   - "Programs are tied to one format … migration registers new ids" (:249-250), against a program id that does not move with the final format (`D/proving.md:415-421`);
   - `PROOF_FORMAT_VERSION` 24/25 as a cargo feature (:254-256) is stale; the run-time registry exists;
   - `MaxProofLen = 512 KiB` (:236) against `MAX_PROOF_BYTES = 256 KiB`;
   - the "Blake2s software in Wasm" row (:291) is stale; Blake2b-256 is final;
   - the 250 ms weight placeholder (:230) against a measured 38M instructions;
   - `io_digest` names the io-hash;
   - the check-order note "program taken from the proof" (:62, modesto's) contradicts `judge`'s venue pin.
7. **`D/identity-and-authority.md` against `D/proving.md`:**
   - §11 (:402-434) puts anchors on JAM through the representative agent, and its "about 10.7M cycles for the settlement verifier measured in slice 1" (:420-421) is stale;
   - §12 (:436-463) puts the registry of spaces and accepted versions on a JAM agent, where proving §6 has Kreivo first;
   - §14 (:511) postpones "the device prover", where proving §8 and §11 decide slice 7's device profile.
8. **`D/core-model.md`:**
   - §9.3 :709 "No global state root on VOS" against proving §7's space root;
   - §9.2 :642 and §11.1 :888-891 have attestables read committed fields through witnesses, where the macro refuses `self` (`messages.rs:119-130`);
   - §11.1 :892-894: public outputs are "return value, roots before and after, program hash" (not the `Statement`);
   - §11.1 :909-912: "10.68M instructions, about 29M gas, one segment; a whole window needs aggregation" is stale;
   - §11.3 :951-971: segment cost guidelines from S5;
   - §11.4 :979-991: the status names `verify_refine_bundle_authenticated` and "replay required"; partly still true, since there is no hiding;
   - §12 :1069-1070 and :1151-1152: "until proofs (slice 5)" and aggregation "once it exists";
   - §18 Q6 and Q7 (:1415-1417) are answered by proving.md and recursion-air.md.
9. **`D/slice-6-clerk.md` is wholly pre-proving-first:**
   - "written for slice 5", steps numbered 5.x (:3, :75-280);
   - the split reversed (:31-35);
   - "No proving is wired … ~15,800 columns" (:17-24), now 8,039 and proved end to end;
   - settlement on JAM, against Kreivo first;
   - registration by first transfer, against the pallet's `register_space`;
   - "to be renumbered", as `D/slice-5-proving.md:12-13` and `D/proving.md:821` say.

   **What it needs from statements still holds:**
   - two roots of one space at two anchors;
   - a rows commitment in the output;
   - output naming both spaces;
   - spans from the last settled anchor (:187-194, :299).

   The spans are what `judge`'s every-root-anchored rule blocks once anchors are pruned (D.12).
10. **`R/spike2-masking.md:107`** recommends published proofs at "(c) at blowup 8 with 26 queries", superseded by format 28's blowup 64 with affine batching. Neither `D/proving.md` §5 nor A.4 says what "one blowup bit traded" means at 64.
11. **Salts:** `R/spike2-masking.md:444` and `R/masking-review.md:112-114` give 4 M31 (124 bits); `ZkParams::salt_columns: 4`. Decided as 8 M31, 248 bits (`D/proving.md:580`; `R/critique.md:107-111`); the prototype must change.
12. **`D/proving.md:668-670`** lists `Record` and `Credential` as built in; `R/kreivo-pallet.md:322` stages only `Record` in P0.
13. **`D/proving.md:1017`:** A.6's fixtures "about 1.2 MB". Built: 380 KB plus the segment fixtures (`D/slice-5-progress.md:3544-3545`). Minor.
14. **`R/masking-review.md:269`** says 19 chips use the paired form; `R/spike2-masking.md:75` says 18. Moot for the wrap.
15. **`D/slice-5-progress.md:4157`** sends the code-quality rest to "the cleanup before master"; the owner now wants it in slice 6.
