# CpuChip constraint authoring rules

A handful of structural rules that aren't obvious from the stwo API but bit us
during Phase 12 development.  Read these before adding new constraints or
lookup emissions to `add_constraints` / `generate_interaction_trace`.

## 1. `finalize_logup_in_pairs` pairs by emission order

Stwo's `finalize_logup_in_pairs` maps frac index `n → n / 2`, batching
consecutive emissions in pairs.  Each pair becomes a single field-quotient
constraint of degree
`max(1 + tuple_degree·2, mult_degree + tuple_degree)`
(roughly: degree shoots up because the two fractions share a denominator
product).

CpuChip declares `LOG_CONSTRAINT_DEGREE_BOUND = 2` — so paired-batch
constraints must stay ≤ degree 4.

**Rule.** Tuples passed to `add_to_relation` should be **degree ≤ 1** in the
fundamental columns.  Multiplicities should be **degree ≤ 1** too.  A tuple
expression like `is_op_a * val_d[0]` is degree 2 and will blow the bound when
paired.  If you need a derived value, materialise it as a column.

**Subtlety: pair parity matters at the chip level.**  CpuChip's
`add_constraints` must emit an EVEN number of `add_to_relation` calls.  The
prover-side `LogupTraceBuilder::add_to_relation_with` /
`add_to_relation_computed` always pair adjacent emissions into shared
interaction-trace columns; `finalize_logup_in_pairs` on the verifier side
matches that column structure 1:1.  Switching the verifier side to plain
`finalize_logup` while leaving the prover-side paired causes a column-count
mismatch and stwo panics with `Option::unwrap() on a None value` in
`pcs/utils.rs`.

So if you add a single new emission, you **must** add a partner alongside —
or defer until another commit adds its own and ship them together.  Two
common patterns:

- **Pair within a feature.**  The Phase 12b-2 SE block emits 4 lookups in a
  trailing block; pair count even, no parity flip elsewhere.
- **Bundle Phase 13b + 13c.**  13b adds the program-memory tuple consumer;
  13c adds the flag-binding emission.  Shipped together = 2 new emissions,
  parity preserved.

## 2. Inserting emissions in the middle reshuffles every later pair

If `add_constraints` already emits `[A, B, C, D, ...]` and you insert two new
emissions between `B` and `C`, the pairing changes from `(A,B), (C,D), ...`
to `(A,B), (X,Y), (C,D), ...` which is fine — but only if all four pairs
stay within the degree bound.

The dangerous variant is inserting **one** emission, or inserting in a
position that splits an existing pair: `(A,B), (C,D)` → `(A,B), (X,C), (D,…)`.
Now `(X,C)` and `(D,next)` are new pair shapes, and a tuple combination
that was fine before may now exceed the degree bound — even though every
emission individually is degree-bounded.

**Rule.** Add new emissions at the **end** of `add_constraints` (and
`generate_interaction_trace`), in **even-count blocks**, so they pair within
themselves and never reshuffle pre-existing pair shapes.

This is what made the Phase 12b-2 SignExtend constraints work after they
initially failed: the 4 nibble-AND lookups were moved from inline (near the
related ground constraints) to a final block right before
`finalize_logup_in_pairs`.  Search for `Phase 12b-2` in `mod.rs` for the
canonical example.

## 3. Verifier-side and prover-side emissions must match exactly

Every `eval.add_to_relation(RelationEntry::new(rel, mult, &[tuple]))` in
`add_constraints` must have a matching `logup.add_to_relation_*(...)` in
`generate_interaction_trace` with:

  - the same relation,
  - the same number of multiplicity columns and the same combining closure,
  - the same tuple values per row,
  - the same emission **order** (so pairing matches).

Mismatches usually surface as `ConstraintsNotSatisfied` with the
`debug_claimed_sums` totals balancing — confusing.  Use that helper to
distinguish "logup imbalance" (totals nonzero) from "structural mismatch"
(totals zero but constraints fail).

## 4. Multiplicity registration on producer chips

A consumer emission `add_to_relation(rel, +mult, &tuple)` only balances if
the producer chip (e.g. `BitwiseLookupChip`, `RangeMultiplicity256`,
`PowerOfTwoChip`) has a matching multiplicity charged in its trace fill.
Trace generation must increment the producer's `bitwise_and_counts`,
`range256_counts`, etc., once per consumer emission.

**Rule.** Whenever you add a new `add_to_relation` to a CpuChip row, mirror
it in the row's trace-fill code with the corresponding `side_note.<x>_counts`
update.  See the `if se_active { ... }` block in `generate_main_trace` for
the canonical paired structure.

## 5. Negative tests are mandatory

Adding a constraint without a matching negative test (a deliberately-wrong
trace that the verifier must reject) leaves you with no proof the constraint
fires.  See `tests/bitmanip.rs` for the pattern: build an honest trace,
mutate one column, assert `prove + verify` panics with
`ConstraintsNotSatisfied`.
