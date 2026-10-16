# The recursion AIR

The narrow, gate-based recursion AIR behind `proving.md` §3.1: its
components, its circuit model, the gate compiler, the in-AIR verifier, the
leaf, the fold and its fixed point, the final wrap and its native verifier,
and the build of slice 5's M1.

- **Status.** [decided] marks the owner's decisions (`proving.md` §12);
  everything else is [proposed].
- **Tags on numbers:**
  - **[measured]**: counted by running code: our chips and the recursion
    AIR's components driven through constraint-framework's recording
    evaluator, compiled to gates, or timed;
  - **[model]**: computed from measured counts with the verifier's structure
    (`SP/count/src/model.rs`, every term named in `SP/logs/count.log`);
  - **[projected]**: time and memory from other provers' measured rates.
- **Paths:**
  - `P` = vos-core's `pvm/proof` (at `b5d42dc2`);
  - `ST` = Stwo at the pin `e1286720` (`crates/`);
  - `UP` = `starkware-libs/proving` at `916aefb5` (`crates/`);
  - `AR` = the tag `voucher-recursion-archive` (`053bd607`);
  - `SP` = `spikes/s5-recair` on branch `spike/s5-recair` (`a2784b49`, local):
    the counting crate `count/` and its logs `logs/count.log`,
    `logs/permute-bench.log`;
  - `R/` = `research/slice-5/`.

## 0. Summary

1. **Three components and one relation.** A Poseidon2-M31 permutation a row
   with sponge and Merkle modes (354 columns), a QM31 gate
   `out = k_m·a·b + k_p·(a⊙b) + k_a·a + k_b·b + k_c·c + Σλ_j·c_j` (41 columns),
   and a DEEP accumulator over eight M31 samples (55 columns), wired by one
   `Gate` relation `(address, l0..l3)` whose addresses and signed
   multiplicities are preprocessed. 458 committed columns with composition,
   every constraint at degree ≤ 3 with paired logup [measured]. No lookup
   tables, so no row floor.
2. **The Poseidon2 body is checked against vos's permutation**: honest rows
   satisfy all 284 S-box and 16 mode constraints in three modes, a changed
   cell is caught, outputs equal `poseidon2::permute` [measured].
3. **The gate compiler is the recording evaluator plus a hash-consed DAG.**
   The window kernel's 22 chips, 4,223 constraints and 1,109 fractions compile
   to 26,812 QM31 gate rows [measured]; per-relation challenges, next-row masks,
   paired and unpaired logup and intermediates need no special case.
4. **A leaf verifying the window kernel's segment** (7,519 columns, blowup 4,
   39 queries) needs 55,307 Poseidon2, 96,324 QM31 and 42,549 DEEP rows
   [model]: the padded shape 2^16 / 2^17 / 2^16, **33.2M cells, 0.16× the
   segment's own 201.7M** (0.054× at the 131k cut), 0.6–1.4 GiB and 1.2–2.6 s
   [projected].
5. **Per verified column and query it spends 56 cells, StarkWare's circuit 824**
   [model / measured]: an eighth of a permutation row for the leaf hash, and
   about an eighth of a DEEP row a sample.
6. **The fold converges at once.** Verifying two children of the padded shape
   needs 30,619 / 41,480 / 3,588 rows, 47% / 32% / 5% of the shape [model].
   The leaf sets the shape; a fold alone would settle at 2^15 / 2^16 / 2^12.
7. **The final wrap** verifies the root fold in 2^14 / 2^15 / 2^11 rows
   (tallest 2^15 ≤ 2^17) [model]: 2.2–4.9 GiB at blowup 64 [projected], about
   85M JAM gas with Blake2b-256 in software, 64M through `0x400`, 117–119M
   masked, about 122 KB unmasked [model].
8. **Corrections to `proving.md`:** a smaller segment class does not shrink a
   leaf (§5); the native transcript mixes the boundary states after the trace
   root and draws relation challenges in chip order (§4.1); one permutation a
   row at degree 3 is 300 columns, not 160 (§1.3); vos's permutation is not the
   reference Poseidon2 arrangement (§11, R2).

## 1. The components

### 1.1 The wiring relation

- **One relation, `Gate`**, with its own challenge pair, as every relation in
  our AIR. A wire is the tuple `(address, l0, l1, l2, l3)`: a QM31, or four M31
  limbs packed (a Merkle digest is two wires, a block of eight queried values
  is two wires).
- **Every operand of every gate is a lookup** whose address and multiplicity
  are preprocessed columns. The multiplicity is signed:
  - **+1, a use** of a wire yielded elsewhere;
  - **−k, a yield**: the gate introduces the wire (a computed output, or a
    guessed value consumed here first) and k other operands use it;
  - **0**: a free witness that touches no other gate (a Merkle sibling).
- **Each address is yielded exactly once,** with the multiplicity of its uses;
  the compiler asserts this and that each relation's total multiplicity stays
  below p. Both are static, so the in-AIR check StarkWare needs for dynamic
  component sizes (`UP/stark_verifier/src/verify.rs:238-311`) has no
  counterpart here.
- **Equality is a use.** A computed value that must equal another is produced
  by a gate whose output lookup uses the other's address. So there is no
  equality component, and no guess costs a row of its own: StarkWare
  finalizes each guess with a gate of its own
  (`UP/circuits/src/context.rs:216-236`), 140,426 guesses in its fold, whose
  QM31 component has 587,275 rows (spike 4b's `fold-b2.log`).
- **Reserved addresses** follow StarkWare (`UP/circuits/src/context.rs:19-22`,
  `UP/circuit_common` `N_RESERVED`): 0 zero, 1 one, 2 `u`, 3–4 the node's
  output digest (two packed wires).

### 1.2 The components, measured

Driven through `InfoEvaluator` and `ExprEvaluator` (`SP/count/src/rec.rs`)
[measured, `SP/logs/count.log` §2]:

| component | pre | main | inter | total | constraints | max degree | fractions | OODS gates (fused) |
|---|---|---|---|---|---|---|---|---|
| `p2` | 33 | 309 | 12 | 354 | 303 | 3 | 5 | 1,892 |
| `qm31` | 17 | 16 | 8 | 41 | 3 | 3 | 4 | 71 |
| `h8` | 7 | 36 | 12 | 55 | 7 | 3 | 6 | 89 |
| composition | | | | 8 | | | | |
| **recursion AIR** | 57 | 361 | 32 | **458** | 313 | **3** | | 2,052 |

Interaction columns pair their fractions (`finalize_logup_in_pairs`), so
masking variant (c) applies unchanged (`R/spike2-masking.md` §3b).

### 1.3 `p2`: Poseidon2-M31, one permutation a row

- **The permutation** is vos's exactly: width 16, R_F = 8, R_P = 14, rate 8,
  its Grain constants, and its round order: add constants, the linear layer,
  then the S-box (`P/src/poseidon2/mod.rs:40-44`, `:283-307`).
- **The S-box at degree 3:** `a = y²` and `out = a²·y`, two columns per S-box.
  The 15 untouched words of a partial round stay linear expressions. That is
  16 input columns plus 142 × 2 = **300 columns, the floor at degree 3**: y⁵
  cannot be reached from a linear y without one committed intermediate. The
  archive's 442 used three columns per S-box at degree 2
  (`AR:zkpvm/tests/recursion_common/mod.rs:62-65`, `:427-435`).
  `proving.md` §8's "about 160 columns" for a permutation a row does not hold
  at degree 3; two rows a permutation would.
- **Modes chain rows instead of wiring them.** The last round's 16 outputs are
  also read at offset −1, so a row's input can be the previous row's output.
  One preprocessed selector a row picks the input
  (`a_j = act_j·m_j + c_j`, eight message limbs `m`, a direction bit `b`):

  | mode | input [0, 8) | input [8, 16) | used for |
  |---|---|---|---|
  | leaf start | `a` | 0 | a lifted leaf's first block (`P/src/poseidon2/mod.rs:381-407`) |
  | leaf continue | `prev[0,8) + a` | `prev[8,16)` | its next blocks, the padding block (`c_j` = 1 then 0) |
  | node | `b ? m : prev[0,8)` | `b ? prev[0,8) : m` | a Merkle path step, chained from the child below |
  | channel start | 0 | `act·m` | the first absorb |
  | channel first | `prev[0,8)` | `act·m` | an absorb after an absorb; the second PoW permutation |
  | channel continue | `prev[0,8)` | `prev[8,16) + act·m` | an absorb's next chunks (`:531-547`) |
  | wired | `m` | `(c_8, c_9, 0…)` | a squeeze `(n_draws, 3)`, the first PoW permutation `(n_bits, 0)` (`:549-580`) |

- **Row order is part of the circuit:** a chained row follows its
  predecessor, and row 0, whose offset −1 is the last row, is never chained.
- **Lookups:** the message as two packed wires (signed multiplicities), the
  output digest as two (signed), and the bit (used in node rows): five
  fractions, three batches, 12 interaction columns.
- **Absorbed values are yielded where they are hashed.** A queried value
  enters the circuit as a limb of a wire the leaf row yields; the DEEP rows use
  it. So a verified column costs one eighth of a row and no guess row.
- **The check** (`SP/count/src/main.rs` `p2_check`) builds a row's honest
  witness with vos's own round functions, evaluates the recorded constraints in
  leaf-continue, node (both bits) and channel-continue modes, and compares the
  outputs with `poseidon2::permute`: all pass, and one changed cell fails a
  constraint [measured].

### 1.4 `qm31`: the arithmetic gate

- `out = k_m·a·b + k_p·(a⊙b) + k_a·a + k_b·b + k_c·c + Σ_j λ_j·c_j`,
  coefficients in M31 from preprocessed columns, one EF constraint of degree
  3. It covers StarkWare's add, sub, mul and pointwise mul
  (`UP/circuit_prover/src/circuit_air/components/qm_31_ops.rs:81-167`) and adds
  a fused multiply-add, scaling and three-term sums in one row. The lane terms
  read one M31 limb of a packed wire `c`: a DEEP sample outside an `h8` block
  is one row, `acc·α^Δ + c_j`.
- **The idioms the verifier needs:**
  - **inverse:** `a·b = 1`, with `b` yielded by the row and the output using
    the `one` wire: one row (StarkWare: a guess, a mul and an eq,
    `UP/circuits/src/ops.rs:194-201`);
  - **M31 constants:** `k_a·one`, one row; QM31 constants from `one`, `u`,
    `i = u² − 2` and `iu`, at most two rows. Constants are fixed by gates, as in
    StarkWare (`UP/circuits/src/finalize_constants.rs:25-82`);
  - **a limb of a packed wire:** `λ_j = 1`, one row;
  - **a bit:** `b·b = b` with the output using `b`: one row; recomposition
    `x = 2·x' + b`: one row; a 31-bit decomposition is 62 rows;
  - **range checks:** by decomposition (a PoW's high bits, a query's high bits).

### 1.5 `h8`: the DEEP accumulator

- `out = acc·μ + Σ_j σ^j·v_j` over eight M31 samples `v` (two packed wires),
  Horner from `v7` down, two steps per intermediate column (degree 3).
- It takes one 8-slot block of a leaf, as the leaf row absorbed it, for one
  sample point whose exponents step by a constant (σ = α^step). The running
  per-point accumulator steps by `μ = α^Δ` between blocks.
- Without it every DEEP sample is one fused gate: the window kernel's leaf then
  needs 436,716 QM31 rows (2^19) instead of 96,324 (2^17), and 48.9M cells
  instead of 33.2M [model].

## 2. The circuit model

- **A circuit is its preprocessed wiring:** every gate's coefficients,
  selectors, addresses and multiplicities, padded to the component sizes. Its
  hash is the preprocessed tree's root. The circuit hash a parent computes is
  `Poseidon2(config words ‖ component log sizes ‖ preprocessed root)`, as
  StarkWare's (`UP/circuit_verifier/src/circuit_hash.rs:24-59`) with our hash.
- **One code path builds the topology and the witness.** As StarkWare's
  `Context<Value>` (`UP/circuits/src/context.rs:58-91`,
  `UP/circuits/src/ivalue.rs:24-69`): with `NoValue` it yields the wiring,
  with `QM31` the same wiring filled; a test asserts they are equal
  (`R/spike4b-stack.md` §2.2).
- **Witness values flow through yields:** each computed value is yielded by
  the gate that computes it; each guessed value (a proof's commitments, sampled
  values, queried values, decommitment hashes, FRI witnesses, nonces) is
  yielded by its first consumer; every other consumer uses the address.
- **Constants are fixed by gates** from `one` and `u`, and `u` by a public
  logup term, as StarkWare's (`UP/circuits/src/finalize_constants.rs:65-82`).
  Zero is `x + x = x`; one is `u·x = u`.
- **Outputs reach a parent as public logup terms.** A node's output digest
  sits at addresses 3–4; its yield counts one use per output, and the parent
  adds the matching terms for `(3, d0..d3)`, `(4, d4..d7)` and `(2, u)` to the
  child's public logup sum, as `UP/circuit_verifier/src/statement.rs:106-147`
  does. A child whose digest differs from the parent's witness fails its own
  logup sum.
- **Padding** appends inert rows (selectors and multiplicities zero) up to the
  component sizes, as `UP/circuit_common/src/finalize.rs:58-78`.

## 3. The gate compiler

**Pipeline** (`SP/count/src/record.rs`, `SP/count/src/dag.rs`):
1. drive a chip's own `add_constraints` with `ExprEvaluator` through
   `drive_chip_oods` (`P/src/framework_access.rs:100-167`), and its
   `InfoEvaluator` for the mask offsets;
2. rename the chip's local names (intermediates, claimed sum, column size,
   columns) so chips share only challenges and constants;
3. hash-cons every constraint into one DAG of QM31 operations, simplifying
   `x+0`, `x·1`, `x·0` and constants;
4. emit gates; a single-use product, negation or M31 scaling folds into the
   linear gate that consumes it.

**What each recorded construct becomes:**
- **QM31 against M31.** At the OODS point every column sample is a QM31, so
  base and extension expressions compile to the same gates. M31 constants
  become coefficients; QM31 constants are wires. A `SecureCol` of four samples
  (an interaction column) is three fused rows.
- **Next-row masks.** A column read at offsets `[0, 1]` or `[−1, 0]`
  (`P/src/trace/eval.rs:27-35`) becomes one sample wire per offset; the
  verifier samples it at `z + offset·g` on the composition bound's step
  (`ST/constraint-framework/src/component.rs:220-232`).
- **Per-relation challenges.** The recording names them `<Relation>_z` and
  `<Relation>_alpha{i}` (`ST/constraint-framework/src/expr/evaluator.rs:40-60`).
  `alpha0` is bound to 1; `z` and `α` are wires from that relation's squeeze;
  the powers cost `size − 2` rows a relation (575 for the kernel's 20
  relations) [measured].
- **Paired and unpaired logup.** `finalize_logup_batched` records its batch
  constraints literally, interaction columns at `[0]` and `[−1, 0]` and
  `claimed_sum · column_size⁻¹` (`ST/constraint-framework/src/lib.rs:193-259`).
  The column size folds to a constant; the claimed sum is the component's wire.
  One fraction a column or two is the same compile.
- **Intermediates** are compiled once and shared through the DAG.
- **Inverses** occur only on constants in our chips (0 left after folding)
  [measured]; any other compiles to one gate.
- **Preprocessed columns** (`get_preprocessed_column`) are the sample wires of
  tree 0, by id.

**Measured, the window kernel's shape** (mask `0x807cffff`, 32k cut;
`SP/logs/count.log` §1):
- 7,519 columns (163 + 5,100 + 2,248 + 8), 8,493 samples, 4,223 constraints
  and 1,109 fractions, max degree 3, 20 relations, as the audit counted
  (`R/audit.md` §2.1, §5.2).
- Next-row masks on 886 main columns (CPU 13, BLAKE2B 354, BLAKE2B_BOUNDARY
  338, MEMORY 15, MEMORY_PAGE 148, REGISTER_MEMORY 18), and `[−1, 0]` on each
  component's last four interaction columns.
- **26,812 gate rows** (38,529 unfused: 22,194 adds, 16,311 muls), 217
  distinct constants. By chip: BLAKE2B 11,090, BLAKE2B_BOUNDARY 5,341,
  MEMORY_PAGE 4,594, CPU 2,699, MEMORY_MERKLE 709, DIVREM 688, MUL 510, the
  other fifteen under 400 each.
- The solvency predicate's shape (no BLAKE2B): 4,538 columns, 15,722 rows; the
  full 32-chip shape: 13,037 columns, 43,980 rows; COMPARE alone: 141 rows.

**Equivalence tests, for every chip of the 32:**
1. **constraint ≡ gate:** at random assignments to samples, preprocessed
   values, challenges and claimed sums, each recorded constraint
   (`ExtExpr::assign`) equals the compiled gates' value;
2. **gate ≡ verifier:** on a real proof's OODS samples, the compiled
   composition equals Stwo's own `evaluate_constraint_quotients_at_point`
   (`ST/constraint-framework/src/component.rs:238-261`), which closes the gap
   between the recording and what the verifier computes;
3. **tamper:** one sample changed makes the composition check fail;
4. **counts pinned:** a regression test pins each chip's gate count, so a chip
   change that bloats its recursion is seen.

## 4. The in-AIR verifier

### 4.1 The transcript, as the native verifier runs it

The leaf replays `P/verifier/src/lib.rs:561-675`, then Stwo's `verify` at the
pin, and a transcript-equality test compares the in-AIR channel with
`Poseidon2M31Channel`'s recorder (`P/src/poseidon2/mod.rs:451-524`):
1. the FS domain, format and PCS config (`P/src/proof.rs:238-252`), then each
   chip's log size;
2. the preprocessed root, then the main trace root;
3. **the boundary states**: 13 registers in, 13 out, pc and ts in and out, the
   two memory roots (`P/verifier/src/lib.rs:592-615`);
4. **the relation challenges**: each active chip in `BASE_COMPONENTS` order
   draws its relations, each relation once, at first use
   (`P/src/lookups/mod.rs:117-125`, `P/src/framework_access.rs:78-87`);
5. the claimed sums, the interaction root; then the composition coefficient,
   the composition root, the OODS point, all sampled values in one mix, the
   DEEP coefficient, each FRI layer's root and folding coefficient, the last
   layer, the PoW nonce, the queries (`P/src/proof.rs:883-920`).

Item 1 and the preprocessed root are constants of a leaf circuit, so the
in-AIR channel starts from their digest as a constant. **`proving.md` A.1
lists the boundary states before the trace root and A.2 orders challenges by
`relations.rs`; the code does neither.** The leaf follows the code, or M0
changes the code and the format together. The boundary chips' claimed sums are recomputed from the
boundary states (`P/src/boundary_binding.rs:116-168`) as public logup terms:
about 800 QM31 rows [model].

### 4.2 The channel

Exactly `Poseidon2M31Channel` (`P/src/poseidon2/mod.rs:489-619`): absorb into
`[8, 16)` over the digest in `[0, 8)` (channel modes), squeeze
`digest ‖ n_draws ‖ 3` (wired mode), PoW as two permutations with
`trailing_zeros(s2[0]) ≥ n` checked by decomposing its high bits. The absorb
carries no length or tag (`absorb([a]) = absorb([a, 0])`,
`P/src/poseidon2/mod.rs:531-547`); that is sound only because the transcript's
shape is fixed, and a circuit pins it.

### 4.3 Merkle paths over lifted trees

- **A leaf is the whole row,** columns sorted by log size, stable
  (`ST/stwo/src/core/vcs_lifted/verifier.rs:123-147`), hashed as one sponge
  (`P/src/poseidon2/mod.rs:376-424`). The sort is a compile-time permutation:
  no in-circuit sort (StarkWare spends about 5 of its 8.46 QM31 rows per column
  and query on it, `R/spike4b-stack.md` §2.3).
- **Per query and tree:** `⌈(n+1)/8⌉` leaf rows chained, then one node row a
  level to the lifting height, the last using the root's address. Paths are
  not deduplicated across queries: the structure stays fixed.
- **Query bits** come from the drawn word: limb extraction, a 31-bit
  decomposition (63 rows a query), and the query's circle point from its bits
  (4 rows a bit) [model].

### 4.4 FRI

- Layer heights and folds follow `ST/stwo/src/core/fri.rs:107-200`: the first
  layer at the lifting height, then line layers down to the last layer.
- **Fold step 1:** the query's and its sibling's leaves (one permutation each),
  then the path. **Fold step above 1:** packed leaves of four QM31 (three
  permutations), the coset's subtree, then the path
  (`ST/stwo/src/core/vcs_lifted/verifier.rs:11-16`).
- **The fold** is `(own + sib) + α·(own − sib)·t`, with `t` the inverse of the
  query point's x (or y in the first layer); the sign of an odd query cancels.
  About 7 rows a pair [model]. The folded value is used by the next layer's
  leaf row: no equality gate.

### 4.5 OODS and the logup sums

- **The composition at OODS:** the compiled gates (§3), one fused row a
  constraint for the random linear combination, one vanishing inverse for all
  components (`ST/constraint-framework/src/component.rs:254-260`), and the
  comparison with the two composition halves.
- **The logup sums:** the claimed sums plus the public terms add to zero
  (the boundary terms for a leaf, the child's outputs and `u` for a fold).

### 4.6 DEEP

- **Samples and points** follow `ST/stwo/src/core/pcs/quotients.rs:77-102`,
  `:291-330`: α-powers by tree and column; a column with two samples gets a
  periodicity sample first, at its second point plus the period of its log
  size. The kernel has 9,467 samples (8,493 plus 974 periodicity) at 20 points
  [measured offsets, counted by that rule].
- **The quotient** is `Σ_p [c_p·S_p(q) − A_p·q.y − B_p] / D_p(q)`
  (`ST/stwo/src/core/constraints.rs:119-134`, `quotients.rs:162-199`), with
  `S_p(q) = Σ α^k·v_k(q)` the only per-sample part, and `A_p`, `B_p` per point
  from `Σ α^k·v_k` and `Σ ᾱ^k·v_k` over the sampled values: two fused rows a
  sample, once.
- **`S_p(q)`** takes one `h8` row per clean block (eight samples of one point,
  exponents in step) and one fused row per other sample: 1,091 rows and 739
  samples a query for the kernel [model]. Each point then costs 6 rows a query
  (its line, its inverse, its numerator, the sum).

### 4.7 Cost per verified column and per query

Window kernel, 39 queries (`SP/logs/count.log`, "slopes") against StarkWare's
measured slopes (`R/spike4b-stack.md` §2.3):

| | recursion AIR [model] | StarkWare's circuit [measured] |
|---|---|---|
| per verified column, per query | **56 cells**: 44 leaf hashing, 12 DEEP | 824 cells |
| per verified column, once | 502 cells: 275 OODS, composition and DEEP sums; 227 channel | ≈3.9k cells |
| width-free, per query | 140k cells: 350 permutation rows (84 paths, 266 FRI), 400 QM31 rows | 146–277 compressions ≈1.4–2.7M cells, plus 5.8–11.6k QM31 rows |

In rows a query, for the kernel: 943 leaf-hash, 84 path and 266 FRI
permutations; 1,091 `h8`; 1,139 QM31 [model].

## 5. Sizing the leaves

Inner parameters: blowup 4, 39 queries, PoW 26, interaction PoW 24, FRI fold
step 1, last layer 1 (`proving.md` §4). Rows [model]; memory and time
[projected] at 5.0–10.9 B per extended cell and 51–110M extended cells per
second, the range of spike 4b's circuit-prover runs and spike 4a's proxy on
our pinned Stwo (`SP/logs/count.log`, "prover throughput").

Every leaf has the recursion AIR's 458 columns; what varies is the rows.

| leaf for | inner columns | rows p2 / qm31 / h8 | padded | cells | memory | time |
|---|---|---|---|---|---|---|
| COMPARE alone (log 12) | 63 | 8,488 / 10,869 / 273 | 2^14 / 2^14 / 2^9 | 6.6M | 0.12–0.27 GiB | 0.2–0.5 s |
| **window kernel, 32k cut** | 7,519 | **55,307 / 96,324 / 42,549** | **2^16 / 2^17 / 2^16** | **33.2M** | 0.6–1.4 GiB | 1.2–2.6 s |
| window kernel, 131k cut | 7,519 | 57,534 / 96,741 / 42,549 | 2^16 / 2^17 / 2^16 | 33.2M | 0.6–1.4 GiB | 1.2–2.6 s |
| window kernel, segment FRI fold step 3 | 7,519 | 49,199 / 102,876 / 42,549 | 2^16 / 2^17 / 2^16 | 33.2M | same | same |
| solvency predicate, 32k cut | 4,538 | 38,911 / 70,235 / 25,233 | 2^16 / 2^17 / 2^15 | 31.4M | 0.6–1.3 GiB | 1.1–2.5 s |
| full 32-chip shape | 13,037 | 85,082 / 138,664 / 68,991 | 2^17 / 2^18 / 2^17 | 66.5M | 1.2–2.7 GiB | 2.4–5.2 s |

- **Against the segment:** the kernel's segment commits 201.7M cells at the
  32k cut and 609.3M at the 131k cut [measured from its shape]: the leaf is
  **0.16× and 0.054×** in cells, as the audit's 0.13× projected
  (`R/audit.md` §5.2). Its proving takes 23 s on the Poseidon2 channel and 5 s
  on Blake2s at 32k (`R/audit.md` §2.3).
- **A leaf's size is the inner proof's width times its queries, not its
  length.** Four times longer segments add 4% of permutation rows (deeper
  paths, two more FRI layers). So `proving.md` §3.3's fallback, a smaller
  segment class for a kernel whose leaf does not fit, does not work: the
  levers are width (the shape per kernel, narrower chips), or a larger padded
  shape. Larger segments make recursion cheaper per step.
- **Headroom:** a kernel-like shape fits up to about 9,300 columns (+24%)
  [model]; Poseidon2 rows bind first. Without the shape per kernel (13,037
  columns) every node would double.
- **Poseidon2 hashing on the prover.** A leaf proof commits about 25M
  permutations (one per eight extended cells, the lifted leaf's prefix reuse,
  `P/src/poseidon2/mod.rs:716-760`, plus nodes and FRI) [model]. vos's scalar
  permutation takes 0.8–2.4 µs by the machine's load [measured,
  `SP/logs/permute-bench.log`]: 20–60 s on one thread, 2.5–7.5 s on eight.
  The rates above assume M0's SIMD hasher.
- **Per window** (8 journals: 16 segments at 32k, 4 at 131k): 31 or 7 nodes
  of the padded shape plus the wrap, about 42–90 s or 13–28 s against 368 s
  or 276 s of segment proving on Poseidon2 [projected]: 0.1–0.25× and
  0.05–0.1×.

## 6. The fold and its fixed point

**The fold node** (`proving.md` §3.4) is a VOS node over StarkWare's
multiverifier structure (`UP/circuit_multiverifier/src/verify.rs:52-90`):
- for each child: its preprocessed root as a witness, its circuit hash
  recomputed and selected from the program's leaf-circuit hashes or the fold
  circuit's hash (a witness word, copied to the output); the STARK verified
  (§4) with the child's outputs as public terms; its preimage re-hashed to the
  digest;
- the program id recomputed from its preimage, both children's equal;
  `left.last + 1 = right.first`, `left.exit = right.entry`; entry flag from the
  left, halt flag and io-hash from the right; the output preimage hashed to
  addresses 3–4. About 37 permutation and 110 QM31 rows beyond the two
  verifications [model].

**A child of the padded shape** has 458 columns, lifting 2^20, 18 FRI layers,
514 DEEP samples at 4 points; verifying it costs 15,291 / 20,686 / 1,794 rows,
384 permutations a query, 243 of them FRI [model].

| | rows p2 / qm31 / h8 | in the padded shape |
|---|---|---|
| the fold (two children) | 30,619 / 41,480 / 3,588 | 47% / 32% / 5% |
| the fold, leaf and fold proofs at FRI fold step 3 | 19,339 / 54,584 / 3,588 | 30% / 42% / 5% |

- **The padded shape** (a format constant, `proving.md` A.4): `p2` 2^16,
  `qm31` 2^17, `h8` 2^16; 458 columns in the order of §1.2 and their
  preprocessed ids; the `Gate` relation; reserved addresses 0–4; blowup 4, 39
  queries, PoW 26, interaction PoW 24, fold step 1, last layer 1, the
  Poseidon2-M31 channel. 33.2M cells, tallest 2^17: every leaf and fold proves
  this many.
- **It converges at once:** iterating "shape → what a fold of two such
  children needs" from the kernel's leaf returns the same shape on the first
  step [model]. A fold alone reaches its own fixed point, 2^15 / 2^16 / 2^12
  (15.0M cells), in two steps from the COMPARE leaf's shape.
- **Headroom:** in rows, the fold leaves 53% of `p2`, 68% of `qm31` and 95%
  of `h8`; in columns, a child could grow by about 3,200 columns before the
  fold outgrows the shape [model]. The leaf, not the fold, sets the shape, and
  `p2` can double without raising the tallest height.
- **Memory and time per fold:** those of the padded shape, 0.6–1.4 GiB and
  1.2–2.6 s, plus its Poseidon2 commitment [projected].

**StarkWare converges at 2^21; this converges at 2^17.** Their fold of two
children needs about 10.3k Blake2s compressions at 80 `blake_g_gate` rows
each, 828k rows (2^20), with 587k QM31 rows, over a 2^20 XOR table
(`R/spike4b-stack.md` §4.2; `UP/circuit_common/src/preprocessed.rs:119-162`),
and their fixpoint iterates the same way (`UP/circuit_params/src/lib.rs:201-215`).
Here a compression is one row, and no table sets a floor.

**Why the archive diverged and this does not.** The archive laid a child's
per-column work out in columns: its verifier was about 2.3 times wider than
its child at every level (ΣW 10,555 → 24,266 → 53,876,
`AR:zkpvm/docs/plans/recursion-completion.md:743`), so no shape could contain
its own verifier. Here a child's columns become rows (an eighth of a
permutation row and at most one DEEP or QM31 row per column and query), and
the verifier's width is the gate set's 458 columns. Above the leaves every
child is 458 columns wide, so each level's work is the same constant. The
archive's verdict that a narrow M31 AIR is "a length effect that doesn't touch
the width divergence" (`:765`) read the first level's cost, Θ(queries ×
7,519), as a width cost: it is paid in rows, once, by the leaf.

## 7. The final wrap

A 1-to-1 node over the root fold (`proving.md` §3.5): it verifies the root in
circuit, pins the fold circuit's true hash as a constant, refuses a root
without `first = 0`, the entry flag and the halt flag, and outputs the program
id and the io-hash as its public logup terms.

| | value | tag |
|---|---|---|
| rows p2 / qm31 / h8 | 15,311 / 20,766 / 1,794 → 2^14 / 2^15 / 2^11, tallest **2^15** (≤ 2^17) | model |
| own parameters | blowup 64, 18 queries, PoW 26, fold step 3, last layer 2^6, Blake2b-256 Merkle and channel | decided |
| cells, extended cells | 7.5M, 481M | model |
| memory, time | 2.2–4.9 GiB, 4.4–9.5 s unmasked; ×1.56–1.6 masked (c): 3.5–7.8 GiB | projected |
| JAM gas, unmasked | 81.1M with the model's Blake2s; **85.2M Blake2b-256 in software (×1.05); 64.1M through `0x400` (×0.79)** | model (`R/spike4a-final-gas.md` §5, §7) |
| JAM gas, masked | 117–119M (×1.37–1.40) | projected |
| proof | about 122 KB unmasked, 164–170 KB masked | model |

- The gas uses spike 4a's fit within 5.8%
  (`gas ≈ −4.2M + 59.3k·C + 2,171·q·C + 17,183·P + 9,376·F`) at 458 columns,
  18 queries and 4 FRI layers. `proving.md` §3.5's 65–70M assumed about 320
  columns; its 6–13 GiB assumed log 17.
- **A narrower wrap**, if gas must fall further: the wrap's own AIR need not be
  the fold's. A `p2` at two rows a permutation (about 180 columns) would bring
  the wrap to about 280 columns and about 67M gas [model], at the price of a
  second component set.

## 8. `vos-final-verifier`

No_std, stable Rust, for x86, wasm32 and riscv64em-javm (`proving.md` §3.6):
- **`vos-recair-air`**, the three components' constraint bodies, shared with
  the prover (the bodies `SP/count/src/rec.rs` states);
- the wrap's constants: its preprocessed root, component log sizes, column
  ids, the parameters of §7, the format number;
- Stwo's core verifier at the pin, FRI fold step 3 and a 2^6 last layer
  (`ST/stwo/src/core/fri.rs:107-200`, admitted after review);
- the Blake2b-256 Merkle hasher and channel, through the host where one exists
  (VOS `0x400`, Kreivo's `blake2_256`), in software otherwise;
- the public logup sum from the program id, the io-hash, `u` and `one`;
- `vos-statement`'s decode and the io-hash recomputation;
- lean as spike 4a's: no preflight, components built once, a fixed-layout
  decode (`R/spike4a-final-gas.md` §4).

**Expected size:** spike 4a's proxy verifier is 344–370 KB as a PVM program
and 208 KB as a Wasm blob [measured]; the recursion AIR's constraints (313,
about 2k QM31 operations) and the statement add tens of kilobytes:
about 0.4 MB PVM, 0.25–0.3 MB Wasm [projected].

## 9. What to adapt, from where

**From StarkWare** (`UP`, Apache-2.0, `UP/Cargo.toml` workspace package):

| source | what we take | what changes |
|---|---|---|
| `circuits/src/{context,ivalue,ops,wrappers}.rs` | `Context<Value>`, `NoValue`/`QM31`, `Var`, guesses, reserved wires | our gate set; signed multiplicities |
| `circuits/src/finalize_constants.rs` | constants from `u`, the `+1` chain, base decomposition | M31 coefficients make an M31 constant one row |
| `circuits/src/{simd,extract_bits}.rs` | packed bit extraction | per query, unpacked for Merkle bits |
| `circuit_common/src/{preprocessed,finalize}.rs` | preprocessed address columns, padding to targets, `elementwise_max` | our components' columns |
| `stark_verifier/src/verify.rs` | the verification flow | our transcript order (§4.1), interaction PoW, no dynamic sizes |
| `stark_verifier/src/{merkle,fri,select_queries,circle}.rs` | per-query paths, layer walk, query points | Poseidon2 chained rows; fold step above 1; lifted leaf order at compile time |
| `stark_verifier/src/{oods,logup,constraint_eval}.rs` | periodicity points, line coefficients, logup terms | DEEP through `h8`; constraints from the compiler |
| `circuit_verifier/src/{statement,circuit_hash,verify}.rs` | public logup terms of outputs and `u`; circuit hash; the build pattern | Poseidon2 |
| `circuit_multiverifier/src/verify.rs`, `circuit_params/src/lib.rs:201-215` | the k-to-1 node; the fixpoint loop | the VOS fold checks |
| `circuit_prover/src/{prover,witness}` | proving a circuit assignment; witness generation | our components; Poseidon2 channel |

**From the archive** (`AR`, the owner's code; its linear layers are Stwo's
example code, Apache-2.0, and keep that attribution):
- `zkpvm/tests/recursion_common/mod.rs:78-132`, `:427-536`: the linear layers
  and the permutation body (re-cut to two columns per S-box, already done in
  `SP/count/src/rec.rs`);
- `zkpvm/tests/fri_fold_chip.rs:9-16`, `:81-99`, `fri_twiddle_chip.rs:85-137`:
  the fold's closed form and the twiddle from query bits;
- `zkpvm/tests/merkle_decommit_trees.rs:328-409`: the leaf sponge and the path
  step's select;
- `zkpvm/tests/channel_chip.rs:532-616` and
  `zkpvm/docs/plans/channel-chip-spec.md:31-55`: rate injection, the PoW
  decomposition, and the exact op order as a test oracle;
- `zkpvm/tests/recursion_deep_evalfin.rs:12-24`: the factored DEEP form;
- `zkpvm/tests/recursion_common/oods_auto.rs` (`StreamBackend`): an
  independent gate list to cross-check the compiler.
- Not reused: the wide interleaved rows, the latches, the per-child verifier.

**Licence plan.** The recursion crates are Apache-2.0, as `vos-pvm-proof`
(`P/Cargo.toml:5`). Each adapted file carries "Adapted from
starkware-libs/proving, crates/<path>, at 916aefb5 (Apache-2.0), modified", a
`NOTICE` lists the files and the Stwo example, and the modification notice of
Apache-2.0 §4(b) is kept.

## 10. The build (slice 5, M1)

Ordered so feasibility is retired first. Weeks are engineer-weeks
[projected].

| # | deliverable | tests | gate | weeks |
|---|---|---|---|---|
| 1 | **The gate VM:** `vos-recair` with `Context`, the three components and their trace generation, the `Gate` relation with signed multiplicities, constants, padding, preprocessing, the circuit hash; the bodies of §1 | random circuits proved and verified natively on the Poseidon2 channel; yields exactly once; tamper per component and mode; the permutation against `poseidon2::permute` | a 10k-gate circuit proves and verifies; degree ≤ 3 audited; a three-component multi-fraction logup at three log sizes proves (§11, R5); `vos-final-verifier`'s skeleton builds on stable no_std | 3–4 |
| 2 | **The gate compiler** | §3's four tests on all 32 chips | 32/32 equivalent; counts within 1% of `SP/logs/count.log` | 1–2 |
| 3 | **The in-AIR verifier's pieces:** channel, lifted Merkle, FRI (fold step 1 and 3), DEEP with `h8`, OODS, logup sums | each against the native code on recorded data; transcript equality with `Poseidon2M31Channel`'s recorder | every piece accepts real data and refuses each tamper | 3–4 |
| 4 | **COMPARE's leaf** (first gate) | a COMPARE proof verified in circuit, the circuit proved and verified natively; tampered OODS sample, queried value, sibling, FRI value and nonce refused | accepted; rows within 15% of 8,488 / 10,869 / 273; ≤ 1 s | 1–2 |
| 5 | **The window kernel's leaf**, and the solvency predicate's: boundary states, entry and exit digests, the A.3 output | spike 3's real segment on the Poseidon2 channel; in-circuit and native transcripts equal | rows within the padded shape; ≤ 24 GiB; ≤ 1× the segment's proving (target 0.13–0.5×) | 2–3 |
| 6 | **The fold and the fixed point** | a fold of two leaves, a fold of two folds within the constant shape; a tree over four segments; refusals: wrong program, gap, broken continuity, prefix, mid-start, wrong child circuit | the fold verifies two folds in the shape; memory and time of a leaf | 2–3 |
| 7 | **The final wrap:** Blake2b-256 Merkle and channel in our Stwo fork, fold step 3 admitted, the wrap circuit, `vos-final-verifier` | the fork's review; tamper tests on fold step 3 and Blake2b; Wasm and JAM-only host verification | ≤ 150M gas unmasked on the JAM-only host; ≤ 2^17 rows; ≤ 24 GiB | 3–4 |
| 8 | **End to end:** `vos-statement`, the window statement and the solvency predicate, golden fixtures (A.6) | every venue judges the fixtures alike | both statements verified natively, in Wasm and on JAM | 2 |
| | **total** | | | **17–24** |

Within M1's 20–28 weeks (`proving.md` §11), with review time on top. Step 1
depends on M0's SIMD Poseidon2 hasher for speed, not for correctness.

## 11. Risks, and the measurement that retires each

| # | risk | measurement |
|---|---|---|
| R1 | **The recursion prover's Poseidon2 hashing**: about 25M permutations a leaf proof, 2.5–7.5 s on eight threads at today's scalar 0.8–2.4 µs [measured, model], one to six times the rest of the leaf | M0's SIMD hasher: a leaf proof's commitment ≤ 0.5 s; otherwise every node takes ×2–4 |
| R2 | **vos's permutation is not the reference Poseidon2:** each linear layer precedes its S-box layer, so there is no final `M_E`, and the full-to-partial and partial-to-full boundaries swap `M_E` and `M_I` (`P/src/poseidon2/mod.rs:283-307` against Plonky3's `poseidon2/src/lib.rs:139-143`, `external.rs:288-336`). It is Stwo's example, whose TODOs flag the order and the internal diagonal (`ST/examples/src/poseidon/mod.rs:125-126`, `:156`) | a cryptographic review of the variant, or the reference order adopted in M0, before the format and the recursion AIR pin it; every commitment changes once |
| R3 | **The gate compiler is wrong** | §3's tests on all 32 chips, gate ≡ verifier on real proofs |
| R4 | **The in-AIR verifier departs from the native one** (periodicity points, lifted leaf order, transcript order, PoW) | piecewise differential tests on recorded transcripts; tamper tests; the external audit (`proving.md` §4) |
| R5 | **The archive's failure with two multi-fraction components** (`AR:zkpvm/tests/merkle_decommit.rs:772-777`, never root-caused) | step 1's three-component test; vos-core's 22-chip Poseidon2 segment proofs already prove (`R/audit.md` §2.3), so it is likely the archive's own |
| R6 | **A wider kernel outgrows the shape** (about 9,300 columns) | each kernel's leaf rows computed at derive time from its shape; a kernel over the limit is refused or takes a larger shape (`p2` 2^17, +70% cells, tallest unchanged) |
| R7 | **The model misses rows** (query points, twiddles, DEEP per point are estimates) | steps 4–5 count real rows; the leaf has 16% headroom in `p2`, 26% in `qm31` |
| R8 | **Time and memory** come from other provers' rates | steps 4–6 measure |
| R9 | **Fold step 3 or the Blake2b channel is unsound** | the fork's review and tamper tests before the format admits them (step 7) |
| R10 | **The wrap's gas**: the fit is on a one-component proxy | step 7 verifies the real wrap on the JAM-only host |
| R11 | **The final verifier needs nightly** (the pin's `portable_simd` is prover-only) | step 1 builds the skeleton on stable for wasm32 and riscv64em-javm |
| R12 | **Signed multiplicities**: a yield by a first consumer is new soundness surface | the compiler's static checks; the audit of the wiring argument |
| R13 | **Masking the wrap** (slice 6) costs more than (c)'s ×1.6 | one masked wrap: ≤ 24 GiB, ≤ 200M gas (`proving.md` §10) |

## Appendix: reproduce

```sh
cd .worktrees/s5-recair/spikes/s5-recair/count   # branch spike/s5-recair, local
cargo build --release --offline                  # nightly-2025-07-14, the repo's toolchain
./target/release/s5-recair-count > ../logs/count.log
```

Under `systemd-run --user --scope -p MemoryMax=16G -p MemorySwapMax=0 nice -n 10`;
the run takes about 2 s. The only change outside `spikes/` lets
`drive_chip_oods` reach BITWISE_AND_BYTE (`6acdc7df`), as the audit's
`d165a7b6` did.
