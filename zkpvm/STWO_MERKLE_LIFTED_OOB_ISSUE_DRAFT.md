# Draft for upstream Stwo issue (do not file from here)

File at: https://github.com/starkware-libs/stwo/issues/new

When ready to file, copy the body below.  This is a SEPARATE issue from the
"lifted protocol degree-≥2" draft at `STWO_UPSTREAM_ISSUE_DRAFT.md`.

---

## Title

> `MerkleProverLifted::decommit` panics with index OOB on small / mixed-size column traces

## Body

We hit an `index out of bounds` panic in `MerkleProverLifted::decommit`
(`crates/stwo/src/prover/vcs_lifted/prover.rs:113`) when calling
`stwo::prover::prove::<SimdBackend, Blake2sMerkleChannel>(...)` with a
single component whose AIR has constraints at degree ≤ 2 (so OODS check
passes) but a small / mixed-size column profile.

The chip in question is a single-component Blake2b compression chip
flattened to bound 1 (max constraint degree 2).  Algebraic check
(`ConstraintsNotSatisfied`) passes cleanly; the failure is later, at
the FRI decommit phase.

### Reproducer shape

- Components: `[Blake2bChip]` (single component).
- Trace: log_size 7 (128 rows), one Blake2bCall input.
- Columns: mix of sizes 1, 8, 16, 64, 128 (deep chip with V-state
  snapshot, M slots, address arrays, etc.).
- PcsConfig: `{ pow_bits: 5, fri_config: FriConfig::new(0, 1, 3, 1),
  lifting_log_size: None }` (cheap test config).
- Stwo rev: `e1286720` (HEAD as of 2026-04-30).

```
thread 'harness_blake2b_isolated' panicked at
  crates/stwo/src/prover/backend/simd/column.rs:111:18:
  index out of bounds: the len is 16 but the index is 16
stack backtrace:
  ...
  3: stwo::prover::vcs_lifted::prover::MerkleProverLifted<B,H>::decommit
  4: stwo::prover::pcs::CommitmentSchemeProver<B,MC>::prove_values
```

### Variations all trip the same family of OOB

| Components | Calls | PcsConfig | OOB |
|---|---|---|---|
| `[Blake2bChip]` | 1 | cheap (pow_bits=5, blowup=1, q=3) | len=16 idx=16 |
| `[Blake2bChip]` | 2 | cheap | len=64 idx=93 |
| `[Blake2bChip, BitwiseLookup, Range256]` | 1 | cheap | len=64 idx=67 |
| `[Blake2bChip]` | 1 | standard (pow_bits=5, blowup=4, q=19) | len=256 idx=302 |

The OOB index always slightly exceeds the column length but stays
within the same order of magnitude; trace-shape dependent.

### Code path being hit

```rust
// crates/stwo/src/prover/vcs_lifted/prover.rs:107-115
let max_log_size = self.layers.len() - 1;
for col in columns.iter() {
    let log_size = col.len().ilog2() as usize;
    let shift = max_log_size - log_size;
    let res: Vec<_> = query_positions
        .iter()
        .map(|pos| col.at((pos >> (shift + 1) << 1) + (pos & 1)))
        .collect();
    queried_values.push(res);
}
```

The doc-comment on line 81 says queries are "indices to the largest
column" — bounded by `2^max_col_log_size`.  But `max_log_size` here is
`self.layers.len() - 1`, which equals `lifting_log_size` (the FRI
parameter), not `max_col_log_size`.  When `lifting_log_size >
max_col_log_size`, or when the column count / sizes are such that
`query_positions` come from a larger domain than the smallest column
expects, the formula `(pos >> (shift + 1) << 1) + (pos & 1)` can
produce indices ≥ `col.len()`.

We don't have enough stwo-internals expertise to definitively diagnose
whether:

1. Query positions should always be bounded by `2^max_col_log_size`
   and our config violates an invariant.
2. The formula on line 113 should account for the difference between
   `lifting_log_size` and the LARGEST column's log size.
3. Column-size mixing is just unsupported in the lifted Merkle layer.

### Workaround / question

Is there a documented constraint on (a) column size profile, (b)
`lifting_log_size` vs. trace size, or (c) component count that we
should respect for the lifted Merkle to work correctly?  None of the
upstream `crates/examples/` use mixed column sizes (wide_fibonacci,
poseidon, plonk, state_machine all have uniform-width traces), so we
suspect this path isn't well-exercised.

For context our migration scope doc lives at:
https://github.com/virto-network/kunekt/blob/zkvm/.wt_alt/crates/zkpvm/STWO_2.2.0_MIGRATION.md
*(adjust path before filing)*

Thanks for the great prover.  Happy to provide a minimal reproducer
crate if useful.

---

## Filing checklist

- [ ] Reduce reproducer to a small, self-contained crate that doesn't
  depend on kunekt/zkpvm — would help the team triage faster
- [ ] Update the migration-doc link path before posting
- [ ] Optional: bisect against pre-lifted-protocol revs to confirm
  this is lifted-Merkle-specific (likely)
- [ ] Subscribe to the issue so a response is visible without polling
