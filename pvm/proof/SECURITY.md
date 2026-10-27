# vos-pvm-proof: security considerations

What a verified proof proves about a PVM execution, what it does not, and
which inputs a deployer must supply honestly. It is descriptive, not a
formal argument. The design is `docs/design/proving.md` (§3.6 the
statement, §4 the security levels, §6 the verifiers) and
`docs/design/recursion-air.md`; [`docs/status.md`](./docs/status.md)
lists what the AIR binds per opcode.

There are two verifying paths:

- **A segment proof,** verified by `vos-pvm-proof-verifier`
  (`verify_standalone`, `verify_kernel_segment`, the chain verifiers):
  format 35. Peers and tests use it.
- **A statement,** a kernel's whole run: its segments (35) verified in
  leaves, folded (32), the root wrapped (28), the wrap verified by
  `vos-pvm-final-verifier` and judged by `vos-statement`. This is what a venue
  (a chain's pallet, the JAM agent) accepts.

## Formats and their bit counts

Each number names one AIR, one channel and one set of parameters
(`src/format.rs`). Counts are conjectured / proven bits at the format's
reference shape, from the security tool (`src/security.rs`):

| format | proofs | channel | counts | floors | status |
|---|---|---|---|---|---|
| 35 | segments, hardened AIR | Poseidon2-M31 | 104 / 62.86 | 100 / 60 | admitted |
| 32 | leaves and folds | Poseidon2-M31 | 108 / 63 | 100 / 60 | reserved: proved and verified inside the recursion, refused by every outside verifier |
| 28 | the final wrap, unmasked | Blake2b-256 | 146 / 82.6 | 100 / 80 | admitted: the tests' and the fixtures', linked by the final verifier under `test-formats` alone |
| 39 | the final wrap, masked (variant (c)) | Blake2b-256 | 146 / 82.70 | 100 / 80 | admitted: what production venues accept |
| 37, 30 | device and credential proofs | Blake2s-M31 | 106 / 62.10, 62.52 | 100 / 60 | reserved |

- **Conjectured** bits are PoW plus queries times log blowup (the ethSTARK
  conjecture, refuted as stated in 2025; the parameters carry a margin for
  its salvaged form). **Proven** bits are the Johnson-bound count with the
  DEEP, ALI and logup terms. The counts are the tool's own model, pinned by
  the format tests; no one outside has reviewed them.
- **The batch `B`** the count by powers takes is every value the DEEP
  quotient batches, one coefficient each: a column's samples and, for a
  column sampled at two points, the periodicity value the fork adds
  (`deep_values_of_column`); `c`, the most of one column, is counted the
  same way, 3. The segment shape batches 10,016 values over 9,020 samples,
  so 37 counts 62.104 (by samples, 62.129); 35's query term binds, 62.86
  either way.
- A verifier rejects a number the registry does not admit, a retired one
  (24 to 27, 29, 31, 33, 34; 36, the legacy segment format, whose 57
  proven bits at its MOBILE shape were below the 60-bit floor; and 40, the
  blowup-64 masked wrap a measured proof was made under, never registered)
  among them, and a proof on another channel than its format's. The
  proof's configuration must equal the format's, and its counts at its own
  shape must reach the floors.

**End to end, the proven bound is the weakest inner format's: 62.86 bits,
not the wrap's 82.6.** Forging a leaf's segment forges the statement. The
conjectured bound is 104. Under Grover's heuristic that is about 31 proven
and 52 conjectured bits against a quantum prover: post-quantum readiness
rests on the conjectured count.

## The segment AIR

- **Hardened in slice 5.** An audit of the AIR in four groups (G1 the CPU
  and the register ledger; G2 memory, page permissions, the root boundary
  and the host verifier; G3 arithmetic; G4 BLAKE2b) found holes that years
  of tamper tests had not. Each was fixed only after a forgery gate, a
  consistent forged trace, was written and accepted by the unfixed AIR; the
  gates stay as tests (`tests/*_gate.rs`). 25 chips, 5,177 constraints.
- **Not yet under a forgery gate of that kind:** PROGRAM_MEMORY's decode
  binding, JUMP_TABLE (one padding fix), the lookup tables, MEMORY_PAGE and
  MEMORY_MERKLE, the witness-input chip, the boundary-binding argument
  (formats v5/v6), the segment cut and closing-flag rule. These are in the
  external audit's scope (below).
- **Recorded, unfixed:** an invalid dynamic jump cannot be proved (no
  kernel needs it); the ledgers cannot prove a gap of 2^27 steps between
  two accesses to one key; a BLAKE2b pointer within 256 bytes of 2^32
  cannot be proved. Each makes an honest run unprovable, never a false one provable.
- **The Ristretto and scalar chips are removed:** they were unsound.
  Precompile ids 110 to 114 are served nowhere, and `derive` refuses a
  kernel that reaches one.
- **The witness input (`0x401`)** is a kernel's only argument channel:
  CpuChip binds the call's destination, capacity and count (at most the
  capacity, written to φ7), and WitnessInputChip writes each byte to the
  memory ledger at the call's timestamp, the addresses a carry chain that
  cannot wrap past 2^32. The register ledger orders reads before writes in
  a step, so a call cannot read its own result. What a kernel read is the
  `witness_input` of its attest.
- **The halt rule:** a halting step's `next_pc` is `PVM_HALT_ADDR`
  (2^32 − 2^16), which no code offset reaches, so a segment ends at that
  pc exactly when it ends at a halt. A trap keeps `next_pc = pc`: a panic
  cannot present as a halt. At the halt φ9..12 hold the io-hash.
- **No gas is proved.** A statement says nothing of a run's cost: the live
  host meters, and live ≡ traced holds for the runs the host completed.
  The prover role bears the cost of a run it chose to prove.
- **Page permissions are part of a program's identity.** A kernel's
  regions (read-only data and the argument window readable; read-write data,
  heap and stack writable; nothing else mapped) are preprocessed constants
  of MemoryPageChip, so they enter the preprocessed root: a store to a
  read-only page, or an access to an unmapped one, does not prove.
- **No chip-isolated proof verifies standalone:** a proof with
  `component_mask = 0` (the explicit-components test path) names no
  boundary chips, and `verify_standalone` refuses it before any
  cryptographic work, as it refuses a mask outside this AIR's chips or
  whose popcount is not the component count.

## Trust boundary: a segment proof

| input to `verify_standalone(proof, hash)` | trusted? | |
|---|---|---|
| `proof.format_version` | no | an admitted number, on its format's channel |
| `proof.interaction_pow` | no | checked against the format's bits before any relation challenge |
| `proof.stark_proof` | no | verified by Stwo, after a hostile-input preflight of every nested length |
| `proof.claimed_sums` | no | must sum to zero; the boundary chips' must equal the sums recomputed from the boundary states |
| `proof.log_sizes` | no | capped by `DEFAULT_MAX_LOG_SIZE` (overridable) |
| `proof.initial_state`, `proof.final_state` | bound | registers, pc and ts bound to the committed boundary columns and to the trace; `memory_root` to the in-AIR page tree of the images; `memory_commitment` is unbound metadata |
| `proof.pcs_config` | no | the format's exactly; Fiat–Shamir-bound |
| `hash`, the preprocessed root | **yes** | the class's program identity: its code, layout and permissions, at its shape. For a kernel, the install's record derives it, and the program id covers it |

The preflight, the format checks, the root against `hash`, the logup sum,
the boundary binding, then Stwo's verifier, in that order.

## Trust boundary: a statement

- **The wrap's verifier pins its own circuit.** `vos-pvm-final-verifier`
  holds the wrap's preprocessed root, its log sizes and format 28's
  configuration as constants (the DEEP batching from the format, never
  from the proof). It refuses bytes over 256 KiB, a non-canonical or
  trailing encoding, and a proof whose shape (trees, samples,
  decommitments, queried values, every column's samples against its
  component's mask) is not the wrap's, all before any Stwo call. It mixes
  the 24 public words (the program id, the io-hash's 16 limbs) before the
  interaction PoW and checks the logup sums with their public terms.
- **What an accepted wrap proves:** a run of the program the id names,
  from its entry state (the kernel's entry pc, ts 1, the loader's
  registers, the image root) through contiguous segments of that
  program's classes to a halt, with that io-hash at the halt. Leaves
  re-do the native verifier's checks in circuit; every fold checks
  adjacency, state continuity and that both children carry the program id
  it recomputes and the fold circuit's hash; the wrap pins that hash and
  refuses a root without position 0, the entry and the halt.
- **The program id is the trust anchor.** A Poseidon2-M31 hash over the
  transpiler version, the program hash, the shape, the segment channel,
  the classes' preprocessed roots, the image root and the leaf circuits'
  hashes. A venue verifies against the id **it pinned** for the kernel
  whose handler acts, by governance, never against the statement's or the
  proof's: otherwise any kernel's proof would do. Anyone with the
  recursion stack recomputes the id from the kernel and its install record.
- **Admitting a program id is admitting an audit of that kernel.** No
  layer checks that a `RootRead` the kernel states is the root its
  multiproof was checked against, that it carries a nonce where its
  statements may repeat, or that its low-entropy outputs are salted: only
  the kernel's code does, and the id pins that code. "Program intent"
  below applies to kernels in full.
- **The statement id** is `BLAKE2b-256("vos/statement/v1" ‖ program ‖
  space ‖ io_hash)`. A venue refuses an id it has accepted, and keys on it,
  never on a proof's bytes (one proof has many encodings, and many proofs
  state one statement). The id does not hash the final format: one run
  wrapped under two formats during a transition is one statement.
- **The rootless rule:** only a root binds a statement's space. A rootless
  statement must claim no space (`SpaceId::NONE`), or one proof would take
  a new id under every space. A kernel that does not state its roots in
  its io-hash (the window kernel, until the SDK does) leaves its handler
  to check what its output says it read.
- **Not yet bound to a venue.** A rootless statement is valid at every
  venue, forever; a rooted one is bound to a venue only by the rule that a
  space anchors on one venue at a time, which `judge` does not check. A
  venue domain, or migration refusing windows in code, is slice 6's
  design. Until a kernel states its roots, no venue should act on its
  statements beyond tests.
- **Every re-pin is a governance event.** A segment format bump (any
  hardening of the base AIR) changes every program id; a change to the
  recursion's compiler or gates changes every leaf circuit's hash, the fold
  circuit's hash and the wrap's pinned root.

## Panic-freedom

A FRAME runtime cannot catch a panic (no unwinding on wasm32 without std;
a panic aborts the block's import), so no guard can wrap the verifier. The
final verifier, `vos-statement` and `vos-anchor` must be panic-free on
every input by construction:

- **The crates' own code:** outside their tests, `clippy::unwrap_used`,
  `expect_used`, `indexing_slicing`, `panic`, `arithmetic_side_effects`,
  `unreachable`, `todo` and `unimplemented` are denied
  (`#![cfg_attr(not(test), deny(..))]` in each `lib.rs`, and in the
  venue's JAM program's two bins and the Wasm blob, which `just
  check-no-std` lints for their targets). Each allowance is in place with
  its reason: QM31's modular addition (the logup sums, twice), the
  compact's big-integer mode (`width` 4 to 8 once checked), `vos-statement`'s
  `fixtures` reader (the harnesses', std, never a venue's), and the JAM
  program's allocator (sums of `Layout` sizes and arena offsets). No lint
  covers `assert!`: the crates hold none outside their tests. `split_at`
  and `copy_from_slice`, which no lint covers either, appear once, at
  lengths equal by construction (`codec.rs`'s big-integer mode).
- **Stwo's code at the pin:** every index, `unwrap`, `expect`, `zip_eq`,
  `assert` and unchecked arithmetic reachable from format 39's
  `masked::verify_masked` (its `replay`, then `verify_values`) and format
  28's `unmasked::verify` (`stwo::core::verifier::verify`) is in the table
  below with what guards it. Two had no guard and are the fork's fix
  (DIVERGENCE-013).
- **Fuzzing:** seven targets (`fuzz/`), a checked-in corpus replayed by
  `just check` (`just fuzz-replay`), and `just fuzz`, a minute a target in
  `ci-full` and five in `slice-gate`.

### Stwo's verify path, audited

"Shape" is the verifier's check before any Stwo call: format 39's
`check_shape` and `samples_fit` (four trees of commitments, sampled values,
decommitments and queried values; each tree's sampled and queried columns
its pinned width; each column's samples its sample points; FRI's inner
layers its rounds; the last layer `2^6`; every limb canonical), and its
fixed layout's pins and bounds; format 28's `check_shape` (four of each,
every limb canonical) and `check_samples` (every tree's columns and every
column's samples the components' masks). "Ours" is a value the verifier
computes from the format, never read from the proof.

| # | site (`crates/stwo/src/core/…`) | guard |
|---|---|---|
| 1 | `verifier.rs` `verify_ex` (28): `trees[PREPROCESSED_TRACE_IDX]` | ours: three trees committed in `replay_prefix` before the call |
| 2 | `verify_ex`: `composition_log_degree_bound() − COMPOSITION_LOG_SPLIT`, `lifting_log_size − log_blowup_factor` | ours: the components at the pinned log sizes (17 − 1), no lifting log size (the header's) |
| 3 | `verify_ex`: `commitments.last().unwrap()` | shape: four commitments |
| 4 | `air/components.rs` `mask_points`: `mask_points[0]`, `preprocessed_mask_points[idx]` | ours: the circuit's preprocessed indices, below the preprocessed tree's columns the verifier committed |
| 5 | `eval_composition_polynomial_at_point` → `constraint-framework` `evaluate_constraint_quotients_at_point` (28), `vos-pvm-recair-air`'s `Rebound`, the same code over the layout's columns (39): `mask[0][idx]`, `sub_tree`'s `assert_eq!` and `get_chunk().unwrap()`, `PointEvaluator::next_mask`'s `mask[interaction][col_index]`, `assert_eq!(mask.len(), N)`, `try_into().unwrap()` | shape: each tree's sampled columns and each column's samples the components' masks (39 `check_shape` + `samples_fit`, 28 `check_samples`) |
| 6 | the same: `coset_vanishing(..).inverse()` | z on the QM31 circle at a point of the trace's coset: about 2^-108 a draw, no grinding reaches it |
| 7 | `circle.rs` `get_random_point`: `(1 + t²).inverse()` | t = ±i: 2^-123 a draw |
| 8 | `pcs/verifier.rs` `commit`: `log_size + log_blowup_factor`; `vcs_lifted` `MerkleVerifierLifted::new`'s `assert!` | ours: the trees' log sizes and the format's configuration, no lifting log size, so the height is the tallest column |
| 9 | `verify_values`: `zip_cols` (`zip_eq` trees, `zip_eq` columns) of sample points × sampled values | shape: four trees, each tree's columns and each column's samples |
| 10 | `verify_values`: `trees.last().unwrap()`, `trees[0].height`, `lifting_log_size − log_blowup_factor` | ours: four trees committed by the verifier, each at least the blowup tall |
| 11 | `pcs/utils.rs` `prepare_preprocessed_query_positions`: the shifts | ours: the trees' heights (the preprocessed tree's 21, the tallest 22) |
| 12 | `verify_values`: `zip_eq` trees × decommitments × queried values × query positions | shape: four decommitments and four queried trees |
| 13 | `vcs_lifted/verifier.rs` `verify`: `col_vals[idx]` | the fork's `QueriedValuesShapeMismatch` (`ca20894`) first: one column a committed column, one value a query |
| 14 | `verify`: `chunk[0]`, `chunk[1]`, `unreachable!` on `idx & 1` | `chunk_by` yields non-empty runs of at most a sibling pair |
| 15 | `verify`: the root layer's `try_into().unwrap()` | ours: the positions drawn below `2^height` (tree 0's mapped into its height), 24 of them, so one root remains; a witness too short or long is an error |
| 16 | `pcs/quotients.rs` `fri_answers`: `assert!` every queried column one value a query; `col[idx]` | every tree's Merkle `verify` (13) passed first, tree 0's on as many positions |
| 17 | `build_samples_with_randomness_and_periodicity`: `expect(ONE_COEFFICIENT_A_VALUE)` | ours: the affine coefficients drawn by `n_deep_values` over the same samples (powers are unbounded) |
| 18 | `accumulate_row_quotients`: `queried_values_at_row[column_index]`; `zip_eq` of a batch's columns × its line coefficients | shape: the sampled columns (whose indices these are) and the queried columns both the trees' widths (28: the Merkle check, 13, holds the queried); the coefficients built from the same batch |
| 19 | `constraints.rs` `complex_conjugate_line_coeffs`: `assert_ne!(z.y, conj(z.y))` | **none at the pin**: Im(z.y) = 0, about 2^-62 a draw, z grindable. The fork's fix: `InvalidStructure` (DIVERGENCE-013) |
| 20 | `denominator_inverses` → `CM31::batch_inverse` → `inverse()`'s zero `assert!` | **none at the pin**. The fork's fix: `InvalidStructure` (DIVERGENCE-013). Unreachable for z on the circle with Im(z.y) ≠ 0: the line vanishes at a base-field circle point only if Im(z) is isotropic, which no circle point's is (proved in its doc) |
| 21 | `fri_answers`: `lifting_domain.at(bit_reverse_index(position, ..))` | ours: positions drawn below `2^lifting_log_size` |
| 22 | `fri.rs` `FriVerifier::commit`: `CanonicCoset::new(..)`'s `try_new().unwrap()`, `LineDomain::new`'s `assert!`, `n_inner_layers − 1` | ours: the degree bound from the verifier's tallest tree (22 − 5); the subtraction only inside the loop over the layers; a wrong layer count is `InvalidNumFriLayers`, a last layer of another size `LastLayerDegreeInvalid` |
| 23 | `FriConfig::new`'s `assert!`s; `draw_queries`' `(1 << log_size) − 1` and `try_into().unwrap()` | ours: the format's configuration; `u32` into `usize` |
| 24 | `decommit`: `expect("queries not sampled")` | sampled in the same `verify_values` |
| 25 | first and inner layers' `verify`: `assert_eq!(queries.log_domain_size, ..)`; `Queries::fold`'s `assert!` | ours: the queries drawn on the first layer's domain and folded by the steps `commit` derived |
| 26 | `compute_decommitment_positions_and_rebuild_evals`: `subset_queries[0]`, `query_evals.next().unwrap()` | non-empty `chunk_by` runs; one evaluation a query (`fri_answers`' one a position, then the folds' one a folded query); a short witness is an error, a long one too |
| 27 | `SparseEvaluation::new`'s `assert!`s; `fold_circle`'s `assert!`, `buffer[0]`, `fold_step − 1`; `fold_line`'s `assert!(n ≥ 2)`, `eval[j]`; `fold_circle_into_line`'s `dst[i]` | ours: subsets of `2^fold_step` built just before, fold step 3 |
| 28 | `build_merkle_verification_inputs`: `next().unwrap()`, `merkle_values[..]`; `domain.log_size() − leaf_log_size` | ours: one value a decommitment position, whole subsets of `2^3` ≥ a packed leaf of `2^2`; packing only on domains of at least `2^2` |
| 29 | `decommit_last_layer`: `zip`, `LinePoly::eval_at_point` | the last layer's `checked_log_size` in `commit` (and 64 coefficients pinned) |
| 30 | `fold_line`'s and `fold_circle_into_line`'s twiddle inversions (`x.inverse()`, `p.y.inverse()`) | ours: points of canonic cosets (y ≠ 0: y is 0 only at points of order at most 2) and of their line domains (x is 0 only at order-4 points, a domain of 2; FRI stops at the last layer's domain, at least 2^7) |

Field inversions elsewhere on the path (M31, QM31) are only 6, 7, 20 and
30.
The channel's draws and `verify_pow_nonce` index nothing from the proof.

### The corpus

`fuzz/replay/<target>/` holds each target's corpus, minimized by
`cargo fuzz cmin` after a five-minute run and kept small; `just
fuzz-replay` (in `just check`) runs every input once; `cargo run --example
paths` lists what each input reaches. The paths it covers are recorded in
`docs/design/slice-6-progress.md`.

## The Stwo fork's open divergences

The workspace pins olanod/stwo at `9e9b4ff6` (`vos/simd-m31-reduce`: the
SIMD backend's Blake2s-M31 digest words reduced canonically over the whole
u32 range, as the verifier reduces them, on `vos/grind-chunks`' `4cd1f83f`:
the prover's parallel grind in chunks of 2^14 nonces, its nonce unchanged,
on `vos/verify-panics`' `c3ec9813`, on `vos/wrap`'s `ab294189`). Its divergence
log (`.claude/skills/paper-implementation-divergence-log.md`) holds two
open items both wraps' counts rest on, and one the verifier's
panic-freedom does:

- **DIVERGENCE-013:** the DEEP quotient's degenerate lines refused, not
  asserted: `complex_conjugate_line_coeffs` and `denominator_inverses`
  return `VerificationError::InvalidStructure` where upstream panicked (a
  sample point whose `y` is its own conjugate; a conjugate line through a
  queried point), each with a unit test from a constructed point. The
  accepted set is unchanged. Branch `vos/verify-panics` (`c3ec9813`), on
  `ab294189`, under the pin.
- **DIVERGENCE-011:** the first FRI round folds by `2^fold_step`, the
  circle fold in it. The security tool counts it so; a model counting the
  circle fold as its own round would differ by about 0.8 bits on the fold
  term. Format 39's FRI tests `2^17`, so its rounds are `[3, 3, 3, 2]` to
  the `2^6` last layer, one more than 28's; its fold term sits 0.19 bits
  above its batching term (82.98 against 82.79). Under the other model the
  fold term would bind first, at about 82.2, still above 80. The round
  list the tool counts must equal the one the fork's `FriVerifier::commit`
  derives from the largest column.
- **DIVERGENCE-012:** affine DEEP batching, opt-in per format (28 and 39),
  counted as `ε_lin(k)` by BCIKS20 Theorem 1.6. soundcalc calls it *linear
  batching* (`pcs.py`'s `_get_batching_error`, `johnson_bound.py`'s
  `get_error_linear`) and cites only BCHKS25; the BCIKS20 names are ours,
  so the audit checks that Theorem 1.6's correlated agreement for affine
  spaces carries BCHKS25 Theorem 4.2's improved `ε_lin`. It carries the
  wrap from 74.7 to 82.6 proven bits, and needs a cryptographer's review of
  the citation and the count: if it is wrong, the wrap is at 74.7, below
  its 80-bit floor (the end-to-end bound, 62.86, is the inner formats'
  either way).
  - **Format 39 rests on it more:** batched by powers, the batching term
    caps 39 at 76.98 (74.48 at blowup 64), at its 538 batched values, and
    at 28's own parameters under masking that term is the one that binds
    (81.74).
  - **Its premise in the masked transcript:** every batched function, the
    masked columns' quotients, the FRI mask's and the blinding columns'
    among them, is committed and every sample mixed before the affine
    coefficients are drawn; the masked verifier takes the batching from
    the format, never from the proof.
  - **If it falls,** format 39 needs a new number: a batching-phase PoW of
    at least 4 bits at blowup 32 (6 at blowup 64), or blowup 8 with 41
    queries (about twice the verify).

## Masking

Format 39's wraps are masked; every other proof (28's wraps, segments,
leaves, folds) is unmasked: its witness (digests, positions, the io-hash,
the fold word) and its trace are in the clear, and segment, leaf and fold
proofs must never leave the prover role.

**Format 39,** the masked wrap, is admitted: `vos-pvm-recair-air`'s masked
AIR, `vos-pvm-recair`'s masked prover and `vos-pvm-final-verifier`'s masked
verifier (pin B's transcript, every pin the format's, the shape checked
before any Stwo call), its bytes a fixed layout with one encoding a proof.
The verifier leaves three facts to Stwo, each pinned and tested: the
trees' widths `verify_values` zips; the FRI rounds `FriVerifier::commit`
derives from the largest column (`[3, 3, 3, 2]`); and FRI's degree bound,
the last committed tree's height less the blowup (17), so the composition
tree is the last and tallest commitment. Its count is the security tool's
under masking variant (c) (`docs/design/research/slice-5/spike2-masking.md`
§3b, `docs/design/research/slice-6/spike6b-masked-bits.md`):

- **What (c) moves:** every main and interaction column is `f + v_H·r`, of
  degree bound `2N` for a tallest component of `N` rows; the composition
  is committed whole at `4N`, never split, and sampled at `π(z)`. So FRI
  tests `k = 4N` at 39's blowup 32, the DEEP term takes `k = 2N`, `d = 3`
  and a factor 2 for `π(z)`, and every other formula stays. The salts
  enter no term (Blake2b-256's collision resistance, which the tool does
  not model, binds them as it binds every tree).
- **146 / 82.70** at 24 queries, PoW 26, the query term binding at
  `m = 5`; 23 queries is the least that clears 80 (80.84). The DEEP term
  is 97.68, ALI 108.38, logup 111.60: the interaction PoW does not bind.
- **Derived, not cited:** the DEEP term's three (c) inputs (`k = 2N`,
  `d = 3`, the factor `2^j`), against Theorem 8 of eprint 2022/1216 with
  the AIR at level `m+1`, the composition at `π(z)` and lifted columns of
  mixed degree. About 15 bits of slack: a factor of 2^10 would not move
  the count.
- **The lifted protocol:** the tool counts the lifted batch as one
  Reed–Solomon code of dimension `4N`, each masked column's `2N` bound
  enforced by one more doubling of its lift. Format 28 already rests on
  this; no paper in the fork's canon analyses the lifted variant.
- **The integer multiplicity:** counts are taken at the best integer
  `m ≥ 3`, as soundcalc takes them, so a small parameter move jumps the
  count (23 queries 80.84, 24 82.70).
- **The reference shape** counts R2's blinding (12 main and 8 interaction
  columns, 2 constraints, a fraction a row a component) and the FRI mask's
  8 columns as designed, and the batch exactly: 538 values, one a sampled
  column and a periodicity value more for each of the 28 columns sampled
  twice (the composition and the FRI mask once each, the salts never). It
  is the shape a test derives from the built masked components, field for
  field. The blinding's own
  soundness (a pole argument in the challenges) is counted only as logup
  fractions.
- **The masked verifier's shape** comes from its own layout (`k = 4N`
  whole, `j = 1`), never from the helpers that subtract Stwo's
  composition split (DIVERGENCE-004), which would put FRI's dimension at
  `2N` (`log_degree_bound` `m+1`) and overstate the batching term by about
  1 bit.

**Zero knowledge** is the argument's: honest-verifier zero knowledge of
the masked IOP, so zero knowledge in the programmable random-oracle model,
conditional on R1 (the randomizer's revealed functionals of full rank),
which the prover checks on every transcript and retries on, and on the FRI
mask `R`'s DEEP coefficients being of rank 4 (all but about 2^-155 of
draws, its 8 columns): `R` is witness-independent, so a simulator draws it
as the prover does, and the real and simulated batches differ by an
`R`-quotient, so FRI's transcript, its unsalted layer trees included, has
one distribution; no check runs for it. The masking's
gates (`vos-pvm-recair`'s `masked_gates`, `leakage` and the masked wrap's
tests; at a medium N under `heavy-gates` in `just test-proof`, at full N
in `just slice-gate`) are a regression
guard, not evidence of it: the soundness gates (acceptance at every size
on both channels, a broken constraint on the first, last and wrap rows
refused forced, the lifted preprocessed columns, the blinding unable to
cancel an unbalanced relation, malformed proofs refused without a panic)
and the statistical leakage gates (per field a χ² on 16 buckets, 4 at 64
proofs or fewer, and a pooled two-sample KS between witnesses;
uniformity, exact at 64 or fewer; α = 10^-3 over the family with
Bonferroni) find gross leaks only: at 2,000 small-circuit proofs a witness
a field leaking about 0.13 in total variation; at the real wrap's 32, by
uniformity, a field leaking about 0.6, and between witnesses only a field
fixed by the witness.

## What leaves the prover role

Only a statement and its masked final proof leave the space's prover role
(`docs/design/proving.md` A.5): segment, leaf and fold proofs, the served
rows, the witness, step counts, memory roots and registers past φ9..φ12
stay with the agent's replicas. The carrier audit checks it on a run
(`just test-carriers`, `vos_checker::carriers`): three nodes prove a read's
statement with the masked prover beside a fourth that replicates nothing
of it, every debug output's environment set, and every carrier's bytes
are searched for the run's own internals, above the floor below: in their
bytes, hex, `Debug` lists, M31 limbs, decimal digits and either byte
order, a store by its rows, each capture path shown to capture by a
canary. The internals are `proving.md` A.5's needles, the masked wrap's
randomness among them (`Kind::WrapRandomness`: each attempt's entropy and
seed, the witness digest, the blinding values, the seeds of the mask, salt
and `R` columns, shown by the prover's watch seam, a dev edge only). `just e2e-chain`
runs it over a whole run on chain: the Kreivo mock's extrinsics, every
work package sent to the JAM statements service on a PolkaJam testnet
with its extrinsics and work report, both venues' anchor chains and the
testnet's own logs and database.

**The search's floor.** A needle too small to tell from chance is not
searched (`node/checker/src/carriers/needles.rs`):
- a byte needle needs at least 8 bytes, 4 of them distinct;
- a number's forms need 4 distinct bytes, so most values below about
  2^16 are dropped;
- a single register and a trace row's value below 2^24 are not needles,
  nor a step count of at most 255 or a power of two;
- the served rows' keys are not needles, and of the rows a run wrote,
  only those served are.

What compensates: each served value's salt and its plain and
domain-prefixed hashes are needles; the served rows and the witness blobs
are searched whole; the re-run's gas is a needle; and the audit's run
writes high-entropy rows by design (`node/host/tests/carriers/audit.rs`),
so its values clear the floor. The served keys and every written value as
needles, and a run over small values, are carried.

| carrier | what it carries | reach | checked by |
|---|---|---|---|
| a submission: the venue's `submit`, Kreivo's `Submit` call, JAM's `Submit` item and its extrinsic | the statement (format, program id, space, public arguments, output, roots) and the format-39 proof | leaves | the audit |
| an anchor: Kreivo's `Anchor` call, JAM's `Anchor` item | space, window, kind, `S_w`, signer, signature | leaves | the audit |
| a JAM work package as it went, its extrinsics, and the work report a guarantor made of it | the items (registrations, anchors, statements) and their proofs; the verdicts, a function of the items | leaves | the audit, every form, on every package a node's or the run's client sent to a PolkaJam testnet, anchors and replays among them, each watched before it went, whether the node's answer came or not, and its report (`just e2e-chain`, the dev tooling's `vos_jam_dev::live::Watch`) |
| a signed Kreivo extrinsic: its envelope | the signer's nonce and the call | leaves | the audit, every form, on the mock's (`just e2e-chain`) |
| a chain's own record of what it was sent: its nodes' logs and database | blocks, guarantees, the packages and their extrinsics, the services' code | leaves | the audit (`just e2e-chain`, `Reach::Recorded`): every needle's bytes, whole hex and `Debug` list, a register file's bytes; not a number's digits, hex or bytes, a hash's hex prefix or a debug output's text, which the chain's own counters, gas, hashes and program bytes hold by chance. What it was sent is searched in every form as the packages and reports above; a statement's encoding and a work report are shown to be in its database as bytes, a report's hash in its log |
| a client's answer | the method's outcome: a read's output | leaves | the audit |
| the JAM statements service's storage, read over RPC at the finalized block | the spaces, anchors, evidence, `Seen` entries and items' outcomes: what the items carried, and the verdicts | leaves | the audit, every form (`just e2e-chain`), but the venue's layout constants and the space's clock, public in this carrier alone (`Audit::carrier_except`) and needles in every other |
| a live run's fault text: `ExitReason`'s `Debug` in `Fault::Agent` (a page fault's address among it; `node/host/src/pvm.rs:177-180, 218`), an executor panic's message (`node/host/src/executor.rs:67-68`, `node/host/src/fault.rs:58-61`) | text of the agent's own run, data-dependent | leaves: the applying node logs it at warn (`node/host/src/group/apply.rs:232-236`), and a query returns it to its caller as `CallError::Failed` (`node/host/src/queries.rs:331`) | not audited: the audit runs happy paths. The replica's logs and an authorized caller hold the agent's state already, so this is not the prover role leaking, but its content is not bounded; the fix (the variant alone, a static panic message with its place) and one audited run of a faulting kernel are carried |
| a panic while a proof is made; a failed proof's error | the panic's place (file and line), not its message; `ProveError::Failed`, which names what failed and no value | leaves (standard error, the logs) | the redacting hook (`node/prover/src/redact.rs`) while a proof is in flight; the audit over the logs |
| logs, at every level | ids, windows, codes, the prover's backlog counts, each proof's time in seconds, and Stwo's `info!` of a proof's size estimate; at debug level, an agent's guest log lines (`refine_host`'s `log`), text the agent's own code writes, which carries whatever that code puts in it | leaves | the audit, for the node's own lines; an agent's are its author's, audited with its code; the time and the size estimate are side channels as below |
| standard error | the node's log: `vos` writes its tracing there, at `VOS_LOG`'s level (info by default); no debug output in a production build | leaves | the audit (the run captures both) |
| the debug outputs: the PVM's instruction trace, `GREY_PVM_DEBUG`'s registers and native code, `CPU_DUMP`, `CPU_EXPR_DUMP`, `ZKPVM_PROFILE` | a run's steps, pcs, registers and trace rows | only a `debug-internals` build (`vos-pvm`'s, this crate's) | `just check-no-debug-internals`: no production edge enables it, and the node's binary names none of them |
| the operator's `/stats` | stage histograms, `refine_gas` and `step_gas` among them: a kernel's gas, so its steps, within a quarter and in sums | the node's operator | not audited: the operator runs the replica |
| the tests' `target/tmp/wrap/` | final wraps (28 of test circuits, 39), their formats, words and judgements' inputs | the test machine | `kernel`'s `wrap_files`: each verifies as a final wrap, and nothing else is there |
| the agent's log, snapshots and peer frames | `Resume` with the served rows; work results with each `Attest` (witness, output, public arguments, roots); `Proven` with the proof's hash | the agent's replicas | the audit: no node proof, memory root or register file |
| frames to a node of the space that does not replicate the agent, and that node's disk and store | heartbeats, placements, forwarded requests | leaves | the audit, every needle |
| the node's blobs and disk | final proofs, large work results, the store | the node | the audit: as above |
| the agent's records of its attests at a cut (`keys::attested`, node-local rows every replica's apply writes alike) | each attest whole (witness, output, public arguments, roots) until its window's roots age past `MaxRootAge` | the agent's replicas, and the snapshots they send | the audit: as above |
| the prover's table | each job's record (`witness_input` among it) until it finishes, its statement, its proof's hash; an unfinished job is dead once its roots age past `MaxRootAge`, and a job of an agent the node no longer replicates goes (`node/prover/src/worker.rs`'s `prune`) | the prover's node | the audit: as above |
| an agent on JAM: its work packages and results (`vos-jam`) | its batch, its rows' witness and its attests whole, served rows included | JAM's validators and DA | by design: an agent on JAM keeps no row from JAM, so a statement of one hides nothing from it |

`RefinePayload`, which carried memory roots, went with the refine-bundle
path (format 36). A proof's time and Stwo's size estimate in the logs,
and the operator's gas stages, reveal the trace's size, as the prover's
time does (the side channel below); a statement is published at the
window's cadence for it.

## The external audit

Required before value rides on a proof. Its scope:

- the base segment AIR, above all the parts listed above as not yet under
  a forgery gate;
- the fork's divergences: the Blake2b channel, fold step 3, affine DEEP
  batching, the completeness backport;
- the security tool's counts (`src/security.rs`), variant (c)'s among
  them. The tool takes soundcalc's convention, the least term binds; a
  union bound over the terms puts format 39 at about 81.2 bits, still
  above 80, but it would not hold at 23 queries, so the 24-query pin is
  the robust one;
- the recursion AIR: the in-AIR verifier, the gate compiler (constraint ≡
  gate), the claimed-sum handling, the `Gate` relation's signed
  multiplicities, the fold;
- the leaf's binding (its entry constants, the io-hash's range checks),
  the wrap, `vos-pvm-final-verifier` and `vos-statement`;
- `derive` (layout to preprocessed columns, its refusals) and the program
  id's derivation;
- the masking: the masked transcript (pin B), R1 to R4, the blinding's
  soundness, and the zero-knowledge argument's premises; later, the public
  sums' re-cut.

Who performs it, and when, is open.

## What a verified proof does not guarantee

- **Program intent:** a proof shows the bytecode ran as the PVM runs it,
  not that the bytecode does what its users think. Auditing it is the
  deployer's, or for a kernel, the governance that pins its id.
- **The boundary's meaning:** a segment proof binds its boundary states;
  whether they are the ones the deployer meant is for the deployer to
  check, against values published out of band.
- **Liveness:** a prover may refuse to prove; a missing proof is not a
  refused one.
- **Side channels:** the prover is not constant-time, and its time reveals
  the trace's size. Statements are published at the window cadence for
  that reason.
- **Cost:** no gas is proved.

## Deployment checklist

- [ ] **Pin each kernel's program id** by governance, recomputed from the
  kernel and its install record by someone other than its prover; pin the
  final verifier's build (its wrap root is a constant of it).
- [ ] **Audit each kernel** whose id you pin: its roots, its nonces, its
  salted fields.
- [ ] **Cap the submission's length** before decoding it; key accepted
  statements on the statement id.
- [ ] **Publish a segment's expected shape and boundary** where a segment
  proof is verified directly; set `max_log_size` to the honest shapes.
- [ ] **Plan for liveness failures:** a fallback or another prover.
- [ ] **Treat `javm` as the reference:** a proof shows a trace matches
  javm's PVM semantics, so a javm bug is a bug here.

## Reporting issues

Soundness or verifier-DoS bugs: a private issue, or the maintainers
directly. Interpreter divergences belong in the javm tracker.

## Stability

- Stwo and javm are pinned to git revisions in the workspace's
  `Cargo.toml`; a deployer who vendors this crate pins them too.
- A proof's encoding is specified by its source and its format number
  alone; keep a verifier build beside any archived proof.
