# Slice 5, spike 4b: which recursion stack to build

Date 2026-10-16. Tags on every claim:
- **[read]**: read in the source, cited by file:line;
- **[measured]**: run in this spike, log cited;
- **[estimated]**: my estimate or model from measured parts, not run.

Paths:
- `VC` = vos-core (`.worktrees/vos-core`, `af548eaf`), read only;
- `SB` = this spike's worktree `.worktrees/s5-spike4b`, branch
  `spike/s5-recursion-stack` (local commits, never pushed);
- `UP` = `starkware-libs/proving` clone at `916aefb5`
  (`/home/daniel/.claude/jobs/8e1fc21e/tmp/s5/proving-src`), not modified (its
  tracked files are untouched; nothing was built inside it);
- `AR` = `SB/spikes/s5-recursion-stack/logs` (every log behind a number);
- `CC` = `SB/spikes/s5-recursion-stack/circuit-chip` (the spike crate: its own
  workspace, nightly-2026-01-15, path dependencies into `UP` and `SB/pvm/proof`).

Machine caveat: spike 4a and this spike's own test suites ran alongside, so
times are noisy; row counts, bytes and peak RSS are not.

## 0. The answers

1. **The port is bounded: days, not months.** `vos-pvm-proof` and the whole
   vos-core workspace build and pass on the monorepo's Stwo and
   nightly-2026-01-15 after five local commits [measured]. 50 compile errors in
   the library and 169 more in tests and benches, all mechanical; four semantic
   changes the compiler did not catch (the OODS proof-of-work, mandatory
   lifting heights, empty trees at height 0, the wire format). Lib 118/118,
   verifier crate 10/10, `test-proof` 491/491 after the fixes, clippy clean
   [measured]. The rest of the workspace (fjall, node, agent) needed nothing but
   two new clippy lints; the PVM guests build on the new nightly. The full port
   with the external verifiers and our Stwo fork is **≈3–5 engineer-weeks**
   [estimated]. On the way it found a **pre-existing completeness bug in
   vos-core** (§1.4).
2. **One of our chips verifies in the circuit, with generated gates, proved
   and verified [measured].** COMPARE (34 main columns, 19 degree-2
   constraints, 10 logup entries over two relations, paired) ran through its own
   `add_constraints` into constraint-framework's recording `ExprEvaluator`,
   and the recorded expressions compiled to circuit gates: no constraint was
   written by hand. The chip's proof verifies in-circuit, a tampered OODS sample
   is refused, the circuit is proved (3.7 s, 3.0 GiB, 183 KB at blowup 4, 35
   queries) and the circuit proof verifies. **Size: ≈824 committed cells per
   inner column per query, plus ≈3.9k per column once, plus ≈150–370
   compressions per query for paths** [measured slopes]. For our kernel-shape
   segment (7,519 columns) that is **≈290–410M cells per verified segment,
   ≈1.4–2.1× the segment's own proving** [estimated]. What changes for our
   chips (§2.4): one (z, α) for all relations, next-row masks (766 columns), and
   the logup batching of 14 chips.
3. **Blake2s only.** The in-circuit verifier hashes Blake2s and only Blake2s
   [read]. A Poseidon2-M31 gate would cut the hash part ≈15–30× and the whole
   recursion ≈4× (to ≈0.4–0.55× of a segment) [estimated]; it touches the gate
   DSL, preprocessing, codegen, witness generation, and makes `stark_verifier`
   generic over the hash: **≈4–7 engineer-weeks** [estimated].
4. **Folding works and fits; the high-blowup root is the memory edge.**
   - A real 2-to-1 fold node (StarkWare's multiverifier over two committed
     Cairo-verifier circuit proofs, padded to the test targets, trace 2^21)
     proved here: **10.5 s, 5.3 GiB, 499 KB at blowup 2 / 70 queries; 18.7 s,
     9.0 GiB, 263,812 B at blowup 4 / 35 queries** (the last equals the privacy
     constant `UP/crates/privacy_circuit_verify/src/consts.rs:5`) [measured];
     blowup 8 was killed at 12 GiB.
   - **The final layer** (a 1-to-1 node over that fold proof, trace 2^20,
     proved on the plain Blake2s channel at a chosen config): **183,652 B at
     blowup 4 / 35 queries (7.0 GiB); 138,992 B at blowup 8 / 24 queries (11.3
     GiB, 17.7 s); blowup 16 killed at 12 GiB** [measured]. Every circuit is at
     least 2^20 rows (a fixed XOR table), so prover memory doubles per blowup
     bit: ≈20 GiB at 16×, ≈40 GiB at 32× [estimated].
   - Their tree's own example re-proves a Cairo leaf and pads every node to
     2^23 rows: ≈20 GiB a node, so it was not run under 12 GiB [estimated].
5. **Masking:** the circuit prover has none of R1–R8 in the form spike 2
   designed; upstream's `add_zk_blinding` is witness-seeded valid-gate padding
   at the leaf only (§5). Masking the final proof means spike 2's design ported
   to the monorepo's Stwo PCS and run on the root's prover; the circuit AIR is
   degree 3 (paired logup), so variant (c) applies unchanged.
6. **Our own AIR's starting point:** the archive holds a full in-AIR verifier
   built as wide interleaved chips (38k lines of tests, 31 of 34 heavy tests
   ignored) that **diverged 2.3× per level** (CL.5a, RED) because it was wide,
   not narrow. Its Poseidon2 constraints, QM31 idioms, FRI fold, Merkle and
   channel chips are reusable as gate bodies; the architecture is not (§6).
7. **Maintenance:** the circuit crates churn 5–63 commits a month (+27k/−21k
   lines in six months); Stwo core 2–15 a month. Git-only: Stwo itself is on
   crates.io only to 2.3.0 (the monorepo is 2.4.0), the circuit crates not at
   all. The no_std story covers Stwo's core verifier only, on stable 1.94 for
   wasm32; a no_std verifier of the circuit AIR does not exist (§7).
8. **Recommendation: the circuit stack**, staged: port now (bounded), build
   the tree on Blake2s-M31 segment proofs first, add a Poseidon2-M31 gate only if
   the recursion's server cost bites; hold the root at blowup ≤ 8 until the
   prover's memory is addressed. It meets the plan's rule on two of three counts
   measured here (port bounded, one chip in-circuit); the third (final-shape
   gas) is spike 4a's. **≈10–13 engineer-weeks to a working tree, ≈18–26 to
   production; own AIR ≈20–28 to a working tree** (§8).

## 1. The port's size

### 1.1 What was done [measured]

In `SB`, `Cargo.toml:123-124` points `stwo` and `stwo-constraint-framework` at
`UP/crates/stwo` and `UP/crates/constraint-framework` by path, and
`rust-toolchain.toml` moves to `nightly-2026-01-15` (the toolchain installed
itself through rustup). Five commits:

| commit | what |
|---|---|
| `2b31b0c2` | the port: 20 files, +242/−343 (lockfile: only Stwo's source and version change) |
| `76ea054c` | the codec fixture's lifting and wire offsets |
| `f7bd8d1a` | spike seam: `draw_chip_lookup_elements` over any channel (§2) |
| `6d9fb59f` | the pre-existing replay bug (§1.4) |
| `93a2938a` | an empty preprocessed tree at height 0 |

Time: about one working day of agent time from the first `cargo check` to the
full suite green, most of it waiting on builds.

### 1.2 The errors, counted and classified [measured]

`cargo check --workspace --all-targets --keep-going` (`AR/port-check-1.log`):
**only `vos-pvm-proof` fails; every other crate builds on the new nightly**
(fjall 3.1.12, the node, agent, raft: nothing to change).

**Library, first pass: 50 errors in 6 files** (`poseidon2/mod.rs` 19,
`proof.rs` 14, `prove.rs` 7, `refine_codec.rs` 7, `refine.rs` 2, `verify.rs` 1):

| class | errors | cause [read] |
|---|---|---|
| field moved | 13 | `pow_bits` moved from `PcsConfig` into `FriConfig` (`UP/crates/stwo/src/core/fri.rs:31-42`, `e836666e`) |
| changed semantics: lifting | 11 | `lifting_log_size: Option<u32>` replaced by mandatory `trace_lifting_log_size` and `preprocessed_lifting_log_size`, and a method (`UP/crates/stwo/src/core/pcs/mod.rs:43-77`) |
| trait restructure | 17 | the digest type moved from `MerkleHasherLifted` to a new `Hasher` trait with `hash_u32s` and `hash_u32s_followed_by_digest` (`UP/crates/stwo/src/core/vcs_lifted/hasher.rs:12-22`, `4c4fe14d`); our Poseidon2-M31 hasher implements it |
| rename | 5 | `MerkleChannel::mix_root` → `mix_hash` (`UP/crates/stwo/src/core/channel/mod.rs:44-49`) |
| signature | 2 | `FriConfig::new` takes `pow_bits` first (`fri.rs:62-73`) |
| removed API | 1 | `pcs::utils::try_get_lifting_log_size` |
| proof format | 1 | `CommitmentSchemeProof::oods_proof_of_work` (`UP/crates/stwo/src/core/pcs/quotients.rs:27-38`) |

**Tests and benches: 169 errors in 10 targets** (`AR/port-check-2.log`): 141
are the same three errors on 47 `PcsConfig` literals; the rest repeat the
classes above, plus `PcsConfig::default` and `PcsConfig::security_bits`
removed. The `poseidon2-channel` feature adds 2 more. Fixed by script.

**What the compiler did not catch** (changed semantics, found by tests or by
reading):
1. **The OODS proof-of-work.** A 16-bit grind before the OODS point
   (`UP/crates/stwo/src/core/proof_of_work.rs:8`, `verifier.rs:80-85`). Three
   places where vos replays Stwo's transcript by hand (`proof.rs`'s structural
   replay, `verify.rs`'s `reconstruct_oods_for_recursion` and
   `extract_recursion_data`) must mix the nonce; the codec must carry it.
2. **Lifting heights are mandatory.** vos let Stwo default them; now every
   prover site computes them from the composition bound
   (`SB/pvm/proof/src/proof.rs`, `with_protocol_lifting`), the transcript mixes
   both heights, the codec carries both, the preprocessed tree is lifted with
   the others. **This changes the preprocessed root, so every program
   commitment changes** (no test in the suite pins one; pins elsewhere must be
   re-made) [read].
3. **An empty tree must sit at height 0** (`UP/crates/stwo/src/prover/vcs_lifted/prover.rs:45`):
   four harness and toy tests failed until the prover put an empty preprocessed
   tree at 0 (`93a2938a`). The checks now admit height 0 for that tree; a
   review must make them admit it only when the AIR has no preprocessed column.
4. **Wire offsets** in the codec's tests (5 lib tests, `76ea054c`).

**Toolchain only:** two new clippy lints (`pvm/runtime/src/recompiler/codegen.rs:1147`,
`pvm/bench/src/bin/dirty.rs:308`), and the settlement guest's target JSON
needs `"target-pointer-width": 64` as a number, not a string.

**Pre-existing, unrelated to the port:** `VC/pvm/proof/src/chips/ristretto/mod.rs:514-552`
writes `std::slice::from_ref` in code the `no_std` verifier build compiles, so
`cargo check -p vos-pvm-proof-verifier --no-default-features` fails on
vos-core today (introduced by `d949e87b`); fixed in `2b31b0c2`.

### 1.3 Tests and guests on the new nightly [measured]

| target | result | log |
|---|---|---|
| `cargo test -p vos-pvm-proof --lib` | 118/118 | `AR/port-test-lib*.log` |
| `cargo test -p vos-pvm-proof-verifier` (prove, verify, hostile proofs, refine bundles) | 10/10 | `AR/port-test-verifier.log` |
| `test-proof` (`--features debug-internals --tests`, 34 binaries) | 487/491, then 491/491 after the two fixes | `AR/port-test-proof-2.log`, `AR/port-test-3.log`, `AR/port-test-chip-isolated.log` |
| `cargo clippy --workspace --all-targets -D warnings` | clean | `AR/port-clippy-3.log` |
| no_std verifier (`--no-default-features`), `poseidon2-channel` | builds | `AR/port-check-5.log` |
| settlement guest (`riscv64em-vos.json`, `-Zbuild-std`) on nightly-2026-01-15 | builds (`settle.elf`) | `AR/guest-settle.log` |
| a bench guest (`hash-software`) on nightly-2026-01-15 instead of its 2026-03-20 | builds | (run inline) |

The smallest proof test (`harness_smoke_bound1_only`) and the full suite pass.

### 1.4 A pre-existing completeness bug the port exposed [measured]

`VC/pvm/proof/src/proof.rs:859-864` replays Stwo's transcript to the query
positions and mixes the OODS samples **one column at a time**; Stwo mixes them
**flattened, in one call**, in the pinned version too
(`~/.cargo/git/checkouts/stwo-59e22971a65c0edb/e128672/crates/stwo/src/core/pcs/verifier.rs:65`).
So the replayed positions were never the verifier's. The check at
`VC/pvm/proof/src/proof.rs:889` compares only their deduplicated **count** with
the queried rows, so it passes unless exactly one of the two position sets has
a duplicate, and then **a valid proof is refused**. On the ported transcript,
`bitmanip::prove_count_set_bits_32` hit it; with the flattened mix it passes
(`6d9fb59f`). On vos-core it fires at random with a probability near
`n_queries²/2^(lifting+1)`: small for large proofs, **≈17% for a 38-query
proof over a 2^12 domain** [estimated]. It cannot accept a false proof (the
full Stwo verification still runs). Worth a fix on vos-core whatever the stack.

### 1.5 The full port, estimated

| piece | weeks [estimated] |
|---|---|
| the mechanical port (done here) | 0.5 |
| the settlement verifier (its own workspace, pinned to our fork `6df2fb30`; its fixture's format changes: the regenerated fixture was reverted, not committed), spike 1's no_std guest verifier, the wasm bench, the fuzz crate | 1–1.5 |
| our Stwo fork (`no-std-pvf-gating`, the masking prototype, the leaf-hash fix `2000c349`) rebased onto the monorepo's `crates/stwo`, or the fork re-cut from the monorepo | 1–2 |
| format version, program commitments and kernel ids re-pinned outside this suite | 0.5 |
| supervised review of the three hand-written transcript replays and the lifting rules | 0.5–1 |
| **total** | **≈3–5** |

Plus the standing cost: upstream's churn becomes ours (§7). The toolchain
moves on its own anyway if wanted (spike 2 §4).

## 2. One of our chips verified in a circuit

### 2.1 How the monorepo builds verifier circuits [read]

- **`stark_verifier`** (`circuits-stark-verifier`) is the generic piece:
  `verify(ctx, &Proof<Var>, &ProofConfig, &impl Statement)`
  (`UP/crates/stark_verifier/src/verify.rs:50`) runs the channel, both proofs of
  work, the logup sum, the OODS composition check, Merkle decommitment and FRI.
  An AIR implements `Statement` (`statement.rs:34-81`) and one `CircuitEval`
  per component (`constraint_eval.rs:218-243`); logup terms go through
  `acc.add_to_relation` and are finalized in pairs by the verifier.
- **`air_code_gen`, `air_infra`, `airs`, `air_compile`** generate the
  `CircuitEval`s for StarkWare's own AIRs (Cairo, the circuit AIR) from an
  `AirFn` DSL; **`eval_air_fn_constraints`** only checks the generated code at
  random points. **Nothing turns an `EvalAtRow` into gates**; for a foreign AIR
  the toy example writes them by hand
  (`UP/crates/stark_verifier_examples/src/simple_statement.rs:64-114`).
- **`circuit_common`** finalizes, pads, blinds and preprocesses a circuit;
  **`circuit_prover`** proves it (`prove_circuit_assignment`,
  `UP/crates/circuit_prover/src/prover.rs:36`); **`circuit_verifier`** verifies
  a circuit proof in-circuit (`verify_circuit`, `verify.rs:81`);
  **`cairo_verifier`** is the Cairo AIR's `Statement`.
- Nothing in the repo proves a verifier circuit for a non-Cairo AIR; the toy
  test stops at checking the circuit.

### 2.2 What was built [measured]

`CC/src/main.rs`:
- **Gates from our own constraints.** `drive_chip_oods`
  (`VC/pvm/proof/src/framework_access.rs:100`) runs COMPARE's `add_constraints`
  through constraint-framework's `ExprEvaluator`. The recorded expressions
  (19 constraints, 10 fractions, their intermediates) compile to circuit gates
  (`add`, `sub`, `mul`, `inv`, `from_partial_evals`); each recorded relation
  combination `Σ αⁱvᵢ − z` is recognized and handed to the verifier's own
  `logup_term`. Nothing about COMPARE is hand-written.
- **The inner proof on the circuit verifier's transcript:** COMPARE's own trace
  and interaction generators, proved with `prove_ex` on `Blake2sM31` in the
  order the circuit replays (salt, FRI config, preprocessed, claim, main,
  interaction PoW, elements, claimed sums, interaction). One spike seam in vos:
  `draw_chip_lookup_elements` over any channel (`f7bd8d1a`), and a replay
  channel that gives both of COMPARE's relations the circuit's single (z, α).
- **The chain:** topology from `NoValue`, the same circuit filled from the
  proof (asserted identical), checked, preprocessed, padded, proved with
  `prove_circuit_assignment`, and the circuit proof checked by
  `circuit_verifier::verify_circuit`.

Results (`AR/chip-c1-l10-toy.log`): `chip proof verified in-circuit: true`;
`tampered OODS sample verified in-circuit: false`; circuit trace 2^20, proved
in 3.66 s, 3,076 MiB, 183,076 B (blowup 4, 35 queries, fold step 4); circuit
proof verified: true.

### 2.3 The circuit's size per verified column and query [measured]

Sweep over copies of the chip (62 committed inner columns each: 34 main, 20
interaction, 8 composition, plus 1 preprocessed), queries and trace size
(`AR/chip-sweep.log`, `SB/spikes/s5-recursion-stack/scripts/chip-sweep.sh`),
inner blowup 4 unless noted. Circuit rows per component; committed cells use
each component's columns including its preprocessed ones: blake_g_gate 115,
qm31_ops 28, triple_xor 49, m31_to_u32 19, eq 10 (`UP/crates/circuit_verifier/src/components/*.rs:5-6`,
`UP/crates/circuit_multiverifier/src/test_utils.rs:78-125`).

| per inner column | qm31_ops | blake_g_gate | m31_to_u32 | triple_xor | eq | cells |
|---|---|---|---|---|---|---|
| per query | 8.46 | 4.65 (1/17 compression) | 1.0 | 0.47 | 1.02 | **≈824** |
| once | 43.4 | 21.9 (OODS mixing) | 4.4 | 2.0 | 2.5 | **≈3.9k** |

Width-independent, per query: ≈146 compressions at a 2^12 evaluation domain,
≈277 at 2^18 (4 Merkle paths and the FRI layers), plus ≈5.8k–11.6k qm31_ops
rows. Totals at copies 1, log 10, blowup 4: 19 queries → 2^18 blake rows; 38 →
2^19; 76 → 2^20. Fold step 4 instead of 1 cuts the blake rows 41% at copies 4.

Note: ≈5 of the 8.46 qm31 rows per column per query are the query sort
(`Statement::sorting_required`, `UP/crates/stark_verifier/src/statement.rs:69`),
which our statement could switch off if our column order matches the commit
order [read, estimated].

**For our segments [estimated, from the slopes]:** a kernel-shape segment has
7,519 columns (audit §2) and a 2^21–2^22 evaluation domain:
- per query ≈ 7,519 × 824 + ≈370 path compressions ≈ **10M cells**;
- once ≈ 7,519 × 3.9k ≈ 30M cells;
- **≈290M cells at 26 queries (blowup 8), ≈410M at 38 (blowup 4)**: 1.4–2.1×
  the segment's own ≈200M (audit §5.2). The leaf circuit is ≈2^21 blake rows
  and ≈2^22 qm31 rows, about StarkWare's own 2^23 leaf for an 8,331-column Cairo
  proof at 70 queries [read: `UP/crates/stwo_run_and_prove_recursive_tree/test_data/circuit_registry.json:27-33`].
- In time: a log-22 leaf ≈20 s and ≈11 GiB at blowup 2, folds padded to the
  same shape likewise; against spike 3's ≈27 s per segment, recursion would
  take **≈1.6×** the segment proving on the server [estimated]. The audit's
  dedicated Poseidon2 AIR projected +15–30%.

### 2.4 What changes for our chips [read, counted]

The recording compiler handles our constraint shapes as they are (degree 2,
degree-3 paired logup, intermediates, preprocessed columns, inverses). What the
in-circuit verifier does not accept:
1. **One (z, α) for every relation**: it draws two elements once
   (`UP/crates/stark_verifier/src/verify.rs:92`) and combines `Σαⁱeᵢ − z`
   (`logup.rs:21-33`). vos draws a pair per relation, about 30 of them
   (`VC/pvm/proof/src/lookups/relations.rs`). Fix: a relation-id first element
   in every tuple (as StarkWare's circuit AIR does), or teach `stark_verifier`
   per-relation elements. The spike faked it by giving COMPARE's two relations
   the same pair.
2. **Next-row masks:** base and preprocessed columns are sampled at one point
   only (`as_single_row`, `UP/crates/stark_verifier/src/proof_from_stark_proof.rs:84-92`).
   **766 of our columns, in 9 chips**, are masked at `[0, 1]` (CPU, both
   BLAKE2b chips, MEMORY, MEMORY_PAGE, REGISTER_MEMORY and three Ristretto
   chips; `VC/pvm/proof/src/trace/eval.rs:31`). Fix: extend `stark_verifier` to
   multi-point masks (OODS samples, quotient terms), ≈2–3 weeks [estimated].
3. **Logup batching:** the verifier always pairs; 14 chips call
   `finalize_logup()` (one fraction per column). Those with more than one
   fraction must pair, or the verifier take the batching per component.
4. **The channel:** inner proofs must use `Blake2sM31Channel` with the
   Blake2s Merkle hasher (`proof_from_stark_proof.rs:19-20`); vos's production
   channel is `Blake2sChannel` (`VC/pvm/proof/src/recursion_pcs.rs:25-30`).
5. **The transcript prefix:** vos's FS domain words, config, log sizes and
   boundary states (`VC/pvm/proof/src/proof.rs:238`) must come out of
   `Statement::claims_to_mix` word for word.
6. Already compatible: last layer degree 0, equal lifting for every tree (the
   port does it), degree ≤ 3, evaluation domain ≤ 2^30 (`verify.rs:57-58`).

## 3. The hash inside the recursion [read, estimated]

- **Blake2s only.** The in-circuit channel mirrors `Blake2sM31Channel`
  (`UP/crates/stark_verifier/src/channel.rs:66-190`); Merkle leaves and nodes
  (`merkle.rs:69-107`), FRI leaves (`fri.rs:111-134`) and `HashValue`
  (`UP/crates/circuits/src/blake.rs:31`) are Blake2s. No Poseidon gate or
  component exists in `circuits`, `circuit_*` or `stark_verifier`; Poseidon252
  appears only as the outer channel of a circuit proof verified natively
  (`UP/crates/circuit_prover/src/prover_test.rs:268-282`).
- **Cost of the Blake2s inside:** one compression is 80 `blake_g_gate` rows
  plus 8 `triple_xor` rows (`blake.rs:308-328`) ≈ 9.6k committed cells for 16
  M31 words, plus a `m31_to_u32` row per word: **≈620 cells per M31 hashed**,
  ≈9.6k per Merkle node.
- **A Poseidon2-M31 gate** (t = 16, rate 8, x⁵ as two degree ≤ 3 steps): ≈300
  base columns plus ≈25 for wiring and addresses ≈ 325 cells a permutation:
  **≈41 per M31 hashed (≈15× less), ≈325 per node (≈30× less)** [estimated].
  The qm31 arithmetic stays, so a segment's recursion drops to **≈80–110M
  cells, ≈0.4–0.55× the segment** [estimated], ≈4× less than §2.3; consistent
  with the audit's "≈5×".
- **What adding it touches** [read]: a gate and gadget in `circuits`
  (`circuit.rs:388-432`); preprocessed address columns, padding and ZK blinding
  in `circuit_common` (`preprocessed.rs:74-117`, `finalize.rs`); an `AirFn` in
  `airs` regenerated by `air_code_gen` into the prover's `FrameworkEval`, the
  verifier's `CircuitEval` (and the Cairo verifier, which we do not need); the
  component lists (`UP/crates/circuit_verifier/src/circuit_components.rs:47-59`);
  witness generation in `circuit_prover`; and `stark_verifier`'s channel,
  Merkle, FRI and `proof_from_stark_proof` made generic over the hash. Our
  constants must be the ones vos's Poseidon2 uses
  (`VC/pvm/proof/src/poseidon2/mod.rs:40-44`). **≈4–7 engineer-weeks**
  [estimated]. Segment proofs on Blake2s-M31 need none of it.

## 4. Folding and the final proof

### 4.1 How they fold [read]

- **`circuit_multiverifier`** builds a k-to-1 node (`build_multiverifier_circuit`,
  `UP/crates/circuit_multiverifier/src/verify.rs:46-121`), used 2-to-1
  everywhere (`UP/crates/circuit_registry/src/schema.rs:84-92`). Per child it
  guesses the proof, the output digest and the preprocessed root, verifies with
  `stark_verifier`, and outputs `blake2s(circuit_hash₀ ‖ out₀ ‖ circuit_hash₁ ‖ out₁)`
  on 8 reserved wires. All children share one config.
- **`stwo_run_and_prove_recursive_tree`** proves Cairo leaves (Cairo proof,
  then a Cairo-verifier circuit proof), folds adjacent pairs, carries an odd one
  up, and stops at one root (`UP/crates/stwo_run_and_prove_recursive_tree/src/lib.rs:142-176`).
  **Every node is padded to one shape**, the elementwise maximum of leaf and
  fold sizes (`UP/crates/circuit_params/src/lib.rs:190-215`), checked as
  "PaddingParity" (`canonical.rs:69-77`).
- **Channels:** leaves and inner folds on `Blake2sM31`; the root on plain
  `Blake2s`, hard-coded, with **the same PCS config as the folds**
  (`UP/crates/stwo_run_and_prove_recursive_tree/src/fold.rs:143-148`); its
  verifier is a Cairo program on Starknet.
- **For VOS** the node must also check `final == next.initial`, equal program
  ids and the io-hash carry: a custom node over the same machinery, not the
  stock output hash.

### 4.2 Run here [measured]

Their tree example re-proves a Cairo leaf and pads every node to the test
registry's 2^23 rows (`test_data/circuit_registry.json:27-33`); from the
measurements below that is ≈20 GiB a node, so it was not run under the 12 GiB
cap [estimated]. Instead, `CC/src/bin/fold.rs` builds the multiverifier over
two copies of the committed Cairo-verifier circuit proof
(`UP/test_data/circuit_multiverifier/proof_cairo.bin`, 182,900 B), padded to
the multiverifier test's targets, exactly as
`test_prove_multiverifier_of_two_cairo_subcircuits` does, and proves it without
writing any fixture:

| node | trace | config (pow:blowup:queries:fold) | time | peak RSS | proof | log |
|---|---|---|---|---|---|---|
| fold, Blake2s-M31 | 2^21 | 26:2:70:4 | 10.5 s | 5.3 GiB | 498,872 B | `AR/fold-b1.log` |
| fold, Blake2s-M31 | 2^21 | 26:4:35:4 | 18.7 s | 9.0 GiB | **263,812 B** | `AR/fold-b2.log` |
| fold, Blake2s-M31 | 2^21 | 27:8:23:4 | killed at 12 GiB | | | `AR/fold-default.log` |
| final layer, Blake2s | 2^20 | 26:4:35:4 | 12.8 s | 7.0 GiB | 183,652 B | `AR/root-b4-q35.log` |
| final layer, Blake2s | 2^20 | 26:8:24:4 | 17.7 s | 11.3 GiB | **138,992 B** | `AR/root-b8-q24.log` |
| final layer, Blake2s | 2^20 | 20:16:19:4 | killed at 12 GiB | | | `AR/root-b16-q19-oom.log` |

(Blowups written as factors. The fold circuit: 587k qm31_ops rows, 828k
blake_g rows, ≈10.3k compressions; the 1-to-1 final node over a blowup-4 fold
proof: 421k qm31_ops, 596k blake_g rows. Final-layer proof bytes are Stwo's
`size_estimate`; the breakdown at blowup 8 is 54 KB trace decommitments, 31 KB
queried values, 48 KB FRI, 6 KB OODS samples.)

### 4.3 Can the root be Blake2s at a high blowup with chosen parameters?

- **In the library, yes** [measured]: `prove_circuit_assignment_with_channel::<Blake2sMerkleChannel>`
  takes any `PcsConfig`; the 2^30 domain cap (`UP/crates/stark_verifier/src/verify.rs:57-58`)
  binds only proofs verified in-circuit, not the root.
- **The tree binary does not** [read]: root channel and config are shared and
  hard-coded (`fold.rs:143-148`); a final layer of our own is a small change.
- **Prover memory is the limit** [measured, estimated]: no circuit is under 2^20
  rows (the 10-bit XOR table has 2^20 rows, `UP/crates/circuit_common/src/preprocessed.rs:119-135`;
  the chip circuit, 24k qm31_ops and 38k blake_g rows, is 2^20 too). Memory doubles with each blowup
  bit: 7.0 → 11.3 GiB measured at 4× → 8×; ≈20 GiB at 16×, ≈40 GiB at 32×
  [estimated]. **The plan's 24 GiB prover fits blowup ≤ 16; blowup 32 needs a
  leaner prover** (Stwo stores coefficients and evaluations, and the circuit
  prover commits every component at its padded size).
- Masked (variant (c), ×1.6 memory): blowup 8 ≈ 18 GiB [estimated].

## 5. Where masking goes [read]

The final proof is the root's Stwo proof; masking lives in the monorepo's
`crates/stwo` prover (in our fork of it) and the circuit prover's call into it
(`UP/crates/circuit_prover/src/prover.rs:50-200`). Upstream's only ZK,
`add_zk_blinding` (`UP/crates/circuit_common/src/finalize.rs:160-177`), adds
`n_queries + 10` random valid gates per component to the **leaf** circuit only,
seeded from the inner Cairo proof's trace root (`UP/crates/cairo_verifier/src/verify.rs:165-168`),
with channel salt 0 (`UP/crates/circuit_prover/src/prover.rs:121-123`).
Internal and root nodes are never blinded; `zk_blinding` is off in the
production registry.

| | in the circuit prover | missing |
|---|---|---|
| R1 rank check | no rank, retry or resample logic | all of it, per column class of the root's 319 columns |
| R2 claimed sums, boundary re-cut | claimed sums mixed in clear (`UP/crates/circuit_verifier/src/circuit_claim.rs:63-66`); 8 outputs and the circuit hash public | blinding of the 11 claimed sums; the outputs are public by design (the digest) |
| R3 FRI mask | FRI on raw quotients (`UP/crates/stwo/src/prover/pcs/mod.rs:243-254`) | the mask codeword and its rank test |
| R4 hedged randomness | witness-only seed | OS ‖ witness digest |
| R5 degree audit | every circuit component at `log_size + 1`, degree ≤ 3 through paired logup; a degree tool exists (`UP/crates/constraint-framework/src/expr/degree.rs:37-75`) unused | the gate; **variant (c) fits as is**, (a)/(b) would need the circuit AIR unpaired and regenerated |
| R6 pinned parameters | one boolean `zk_blinding` per leaf (`schema.rs:79-80`) | salts, mask sizes, `h`, levels in the format |
| R7 carriers | outputs, circuit hash, claimed sums, roots, nonces, salt 0; off-proof the tree's `packed_output` carries leaf preimages (`fold.rs:61-64`) | the audit, and keeping leaf outputs out of anything that leaves the prover role |
| R8 cost | none measured upstream | measure on the root (≈11.3 GiB unmasked at 8×) |

Also missing upstream: salted Merkle leaves (`UP/crates/stwo/src/prover/vcs_lifted/prover.rs:35-60`)
and a composition committed whole (`UP/crates/stwo/src/prover/mod.rs:57-72`).
In short: spike 2's design, ported from the pinned Stwo's API to the
monorepo's, applied to one prover call. The work is the same under either
stack, plus a port of the prototype (≈1 week [estimated]) under this one.

## 6. Our own AIR's starting point [read, through a delegated source read with citations]

- **The tag** `voucher-recursion-archive` is `053bd607` (2026-07-01), on no
  branch; 257 commits from merge-base `2641d72a`; 354 files, +97,490/−3,736,
  of which 197 files (+34,852) are a vendored Stwo.
- **The PCS plumbing is already on vos-core:** `recursion_pcs.rs` is
  byte-identical (`VC/pvm/proof/src/recursion_pcs.rs`, 88 lines),
  `poseidon2/mod.rs` differs cosmetically (767 lines: t = 16, R_F = 8, R_P =
  14, rate 8, Grain constants, the hasher, the channel, a recorder, SIMD leaf
  hashing), and so are the host hooks `reconstruct_oods_for_recursion`,
  `record_canonical_transcript`, `extract_recursion_data`
  (`VC/pvm/proof/src/verify.rs:517`, `:984`).
- **What only the tag holds:** 47 recursion test files, **38,083 lines**: a
  Poseidon2 permutation AIR at one permutation a row (**442 columns**, x⁵ as
  three degree-2 constraints, `zkpvm/tests/recursion_common/mod.rs:65,427-533`),
  a channel-replay chip (522 columns), QM31 ops, FRI fold (25 columns), twiddle
  and chain chips, Merkle decommitment (merged, streamed, real trees), OODS
  (`oods_auto.rs`, an auto-witnessing evaluator over a chip's `evaluate`, the
  same idea as §2's compiler), DEEP quotients, a join with latched challenges,
  and `ChildFullEval`, the full per-child verifier (`recursion_child_full.rs`,
  12,330 lines).
- **Test state:** 31 of 34 tests in `recursion_child_full.rs` are `#[ignore]`
  (20–30 GiB); the light gates run by default; one real bug is open (a
  producer/consumer split of the permutation relation fails,
  `merkle_decommit.rs:772-777`).
- **Why it ended** (`zkpvm/docs/plans/recursion-completion.md:743-745` on the
  tag): **the in-AIR self-verify diverged**: a verifier of an O_k child is
  ≈2.3× wider than the child (ΣW 10,555 → 24,266 → 53,876 columns), because the
  verifier was built as wide interleaved rows whose width follows the child's;
  and the verifier-as-guest route was 606–752M instructions a join with a
  69 GiB wall. vos-core's record (`VC/pvm/proof/docs/design/recursion-decision.md:27-30,66-67`)
  rejected "a narrow app-specific AIR".
- **What this means for our own AIR** [estimated]: a recursion AIR converges
  only if its width is constant and its work goes into rows, which is what
  StarkWare's gate design does and what this spike measured (a 319-column fold
  node verifying two 319-column proofs fits 2^21). The archive's gate bodies are
  reusable (permutation constraints, QM31 idioms, FRI fold, Merkle, channel,
  the auto-OODS evaluator); its architecture is not. Our own AIR means writing a
  gate VM (DSL, wiring relation with preprocessed addresses, prover, in-AIR
  verifier, multiverifier): StarkWare's equivalents are ≈13.5k lines of
  non-test, non-generated code plus 5.3k generated
  (`UP/crates/{circuits,circuit_common,circuit_prover,circuit_verifier,stark_verifier,circuit_multiverifier,stwo_run_and_prove_recursive_tree}`,
  counted here).

## 7. Maintenance [read, counted]

**Churn**, commits a month (October is 15 days), `git log` in `UP`:

| crates | Apr | May | Jun | Jul | Aug | Sep | Oct |
|---|---|---|---|---|---|---|---|
| `stwo` | 9 | 1 | 3 | 13 | 15 | 7 | 2 |
| `constraint-framework` | 2 | 2 | 1 | 6 | 3 | 0 | 2 |
| circuits, circuit_common/prover/verifier, stark_verifier, multiverifier | 13 | 31 | 63 | 40 | 34 | 19 | 5 |
| recursive tree, leaf prover, privacy, circuit_params | 2 | 4 | 12 | 27 | 32 | 16 | 1 |
| air_code_gen, air_infra, air_common, airs, eval_air_fn_constraints | 17 | 19 | 8 | 12 | 2 | 3 | 4 |

Lines since 2026-04-15: Stwo and the constraint framework +4,329/−4,028; the
circuit crates +27,020/−20,644. 633 commits to the whole repo in six months;
46 to Stwo since our pin (spike 2 §1). The circuit crates were split into the
monorepo on 2026-02-18 (`6df6be91`) and the tree binary appeared 2026-06-16
(`01f63c06`): young code.

**Publishing:** no crates.io workflow in the repo; artifacts go to a GCS
bucket (`.github/workflows/upload-artifacts-workflow.yml`). On crates.io,
`stwo` has 1.0.0 to **2.3.0** (2026-06-25); the monorepo is 2.4.0; the circuit
crates are not published (`circuits-stark-verifier` returns 404). So: **git
dependencies by rev**, as vos pins today.

**no_std:** `ensure-verifier-no_std/` builds `stwo` and
`stwo-constraint-framework` with `default-features = false` for
`wasm32-unknown-unknown` on stable **1.94.0** (its `rust-toolchain.toml`; CI
`.github/workflows/stwo-ci.yml:174-175`). It covers Stwo's core `verify` only.
The circuit AIR's components live in `circuit_prover` (std, nightly
`portable_simd`); the circuit verifier crates use `std`. **A no_std native
verifier for our final proof (JAM, Kreivo) means extracting the 11 generated
components' `FrameworkEval` code (`UP/crates/circuit_prover/src/circuit_air/components/`)
and the circuit-hash mixing into a crate of our own**, ≈2–3 weeks [estimated].

**License:** Apache-2.0 (`UP/Cargo.toml` workspace package).

## 8. The comparison

Engineer-weeks [estimated]. Masking (5.4) is the same work under both stacks
and is left out, except the prototype's port.

| piece | circuit stack | own AIR |
|---|---|---|
| move to the monorepo's Stwo and nightly | 3–5 (§1.5) | 0 (or later, on its own) |
| our AIR conformed to the in-circuit verifier: one (z, α), next-row masks, batching, channel, transcript prefix | 5–8 | 0 (native) |
| gates from our chips (the recording compiler, all chips, equivalence tests) | 2–3 | 2–3 (the same compiler, for our own gate set) |
| the recursion VM itself: gate DSL, wiring, preprocessing, prover, in-AIR STARK verifier (FRI, Merkle, OODS), Poseidon2 gate | 0 (exists) | 12–16 |
| the VOS statement: program id, io-hash, anchor, boundary states, public logup sum | 2–3 | 2–3 |
| the VOS fold node: seam, program id, padding classes | 2–3 | 3–4 |
| the final layer on Blake2s, memory at high blowup | 1–2 | 1–2 |
| a no_std native verifier of the final AIR (JAM, Kreivo) | 2–3 | 1–2 (our own AIR, already no_std-minded) |
| the masking prototype ported to the new Stwo | 1 | 0 |
| tests, hardening, soundness review | 2–3 | 3–4 |
| **to a working tree (first statement folded, verified natively)** | **≈10–13** | **≈20–28** |
| **to production** | **≈18–26** | **≈27–37** |
| optional: Poseidon2-M31 gate | +4–7 | included |

**Recursion cost per segment** [estimated, §2.3, §3]: circuit stack with
Blake2s inside ≈1.4–2.1× the segment's own proving (≈1.6× in time); with a
Poseidon2 gate ≈0.4–0.55×; a lean dedicated AIR ≈0.13× (audit §5.2, projected,
never built). The final proof is the same shape under both: ≈319 columns, 2^20
rows, ≈139 KB at blowup 8.

**Risks, circuit stack:**
- **Upstream churn becomes ours:** the circuit crates moved +27k/−21k lines in
  six months, are young, unpublished and git-only; every bump re-runs §1's port.
- **Memory of a high-blowup root:** ≥2^20 rows by construction; blowup 16 ≈20
  GiB, 32 ≈40 GiB; masked ×1.6.
- **The verifier is not general for us yet:** next-row masks and per-relation
  elements are changes in their soundness-critical verifier code, which we then
  carry as a fork until (if) upstream takes them.
- **Recursion is 4× dearer than it needs to be** until a Poseidon2 gate exists.
- **Masking a prover we do not own**, and its single-(z, α) logup and paired
  constraints are fixed by their codegen.

**Risks, own AIR:**
- **The fixed point:** our previous attempt diverged 2.3× a level; a narrow gate
  VM converges in StarkWare's design, but ours would be new code proving it
  again.
- **≈2× the effort and all of it soundness-critical code without an outside
  user or audit**; the longest pole of slice 5 grows to 5–7 months.
- **Nothing to measure against until it exists**; every number here for it is
  projected.

**Recommendation: the circuit stack.**
- The plan's rule (5.0 item 4): the port is bounded (measured: green suite in a
  day, ≈3–5 weeks in full), one chip verifies in-circuit (measured, generated
  gates, proved and verified), and the final-shape gas is spike 4a's to measure
  (shape here: 319 columns, trace 2^20, Blake2s, blowup 8 / 24 queries,
  ≈139 KB).
- Stage it: port; conform our AIR (relation ids, next-row masks, batching,
  Blake2s-M31 segments); build the leaf statement and the VOS fold node; root
  at blowup ≤ 8 (11.3 GiB measured) until the prover's memory allows more; add
  the Poseidon2-M31 gate when recursion's server cost matters.
- Phones are unaffected by the choice: device-made segment proofs stay on
  Blake2s-M31, which phones hash fastest, and enter the tree as leaves; folds
  run in the space's prover role.
- Independently of the stack: fix vos-core's replay bug (§1.4) and its no_std
  build (§1.2).

## 9. What was built, and how to reproduce it

Commits on `spike/s5-recursion-stack` (local): the five in §1.1, and the spike
crate, scripts and logs (`SB/spikes/s5-recursion-stack/`).

```sh
# the port (in SB)
cargo check --workspace --all-targets
cargo test -p vos-pvm-proof --features debug-internals --tests --no-fail-fast -- --test-threads=2
# one chip in the circuit (in CC; nightly-2026-01-15, lockfile seeded from UP's,
# since UP pins a yanked zip 0.6.6)
cargo build --release
S4B_COPIES=1 S4B_LOG=10 S4B_INNER=10:2:38:1 S4B_OUTER=20:2:35:4 target/release/s5-circuit-chip
../scripts/chip-sweep.sh ../logs/chip-sweep.log
# a fold node, then the final layer in a fresh process
S4B_FOLD=26:2:35:4 S4B_FOLD_PROOF=/tmp/fold.bin target/release/fold
S4B_FOLD=26:2:35:4 S4B_FOLD_PROOF=/tmp/fold.bin S4B_ROOT=26:3:24:4 target/release/fold
```
(`S4B_*` FRI configs are pow:log_blowup:queries:fold_step; run each under
`systemd-run --user --scope -q -p MemoryMax=12G -p MemorySwapMax=0 nice -n 10`.)

## Caveats

- **The segment-level numbers are models** from one chip's measured slopes
  (COMPARE, log 10–16, 62 columns a copy) extrapolated to 7,519 columns and a
  2^21–2^22 domain; constraint density per column is taken as COMPARE's.
- **The fold and final-layer measurements** use StarkWare's own circuit proofs
  (a Cairo verifier) as children, not ours; the node and final shapes are the
  same machinery our tree would use.
- **Memory beyond 12 GiB is extrapolated** from the measured doubling per
  blowup bit.
- **The chip ran with one (z, α) for both its relations** (§2.4); the gates for
  its constraints are its own.
- **The archive** was read through a delegated source read with file:line
  citations, spot-checked at `recursion-completion.md:743-745` and
  `recursion-decision.md`.
- **Effort figures** are estimates; the port's is anchored on the port done
  here.
