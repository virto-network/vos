# Ledger read-consistency (register + RAM)

`RegisterMemoryChip` and `MemoryChip` enforce read-after-write against a
from-scratch prover: each read's value is bound cross-row to the previous
same-key row's value, the ledger is sorted by `(key, ts)`, and `is_write`
is in the logup tuple. This is the column→trace half of the boundary
public-input binding: without it `final_state.registers` (and so the
io-hash in φ9..φ12, which the closing read pins) would be forgeable. The
gates are `tests/gates/ledger_readconsistency_gate.rs`.

As built, the design below differs in three ways: (1) the sortedness
range-check is a self-contained **boolean bit-decomposition**, not
Range256 (the consumer pass runs with an immutable `&SideNote` and cannot
bump multiplicities); (2) `LOG_CONSTRAINT_DEGREE_BOUND` stays at 1 — the
prover rejects any value > 1 on these chips — so the gadget is flattened
to degree ≤ 2 with helper columns (register: `BothRealH` + `OrderValH`;
RAM: `AdvLoH` + `AdvHiH` for the 16-bit-half lexicographic address
compare); (3) a `≥ 1 padding row` guarantee makes the cyclic last→row-0
wraparound always a padding transition, so the gadget never fires across
it.

## The gap

Read-after-write enforced only via `is_read · (value − prev_value) = 0`,
with `prev_value` a **free** main-trace witness column, binds nothing:

- no `#[mask_next_row]` would tie `prev_value[i]` to the previous ledger
  row's `value[i-1]`;
- no constraint would bind `IsSame{Reg,Addr}Next`;
- no `(key, ts)` sortedness / timestamp-monotonicity check would hold.

So a from-scratch prover sets a read row's `prev_value := value (= a lie
L)`; read-consistency holds (`L − L = 0`) while the *actual* previous
ledger row carries the true value `T ≠ L`. This forges any register/RAM
read — including the synthetic closing read (`RegisterMemoryClosingChip`)
that pins `final_state.registers`, hence the io-hash. A negative test that
forges the *side-note* and then runs the honest trace filler exercises the
filler, not the constraint; a gate must tamper the trace itself.

### Gate tests — `tests/gates/ledger_readconsistency_gate.rs`

Each builds an HONEST `ComponentTrace`, tampers a read row's cells
(bypassing the filler — exactly what a from-scratch prover does), and
asserts the constraints REJECT:

- **prev_value tamper:** a register read (φ2 written 12@ts1, read 12@ts2,
  Value+PrevValue → 99) and a RAM read (StoreIndU8 0x42→[0x1000] then
  LoadIndU8, Value+PrevValue → 0x99);
- **reorder:** a stale write placed immediately before the closing read or
  a read (defeats value binding alone; closed by sortedness);
- **is_write flip:** the closing read or a read marked `is_write=1` so
  read-consistency skips (defeats value binding + sortedness; closed by
  the `is_write` tuple binding).

## Why all three sub-fixes are necessary (attack-by-attack)

The logup balance already fixes the *multiset* of producer tuples; the prover's
only freedom is the ledger row **order** + the free witness columns
(`prev_value`, `IsSame*Next`, and — for registers — `is_write`). The closing
producer's value (`final_regs[r]`) is the one freely-chosen value.

1. **prev_value tamper** (the gate tests) → **cross-row value binding**.
2. **reorder** (put a stale write right before the closing read so its prev is a
   lie) → **(key, ts) sortedness** (closing_ts = last+1 is max, so with ts
   non-decreasing the closing read sorts last → its predecessor is the true last
   access). Timestamps are per-STEP counters chained +1 by CpuChip and bounded
   `< 2^28 < p/4`, so **non-decreasing (≤)** monotonicity is SUFFICIENT (equal-ts
   collisions occur only within one step and are self-policed by
   read-consistency + the bound tuple values).
3. **is_write-flip** (mark the closing/any read `is_write=1`; read-consistency is
   gated on `is_read` so it skips → value free) → **bind `is_write`**. A
   column outside the tuple a from-scratch prover sets freely, so the
   register tuple carries `is_write`, as memory's does
   (`(addr[4],value[1],ts[8],is_write[1])`). Needed for ALL reads, not just closing:
   a normal read flipped to a write decouples its value from the last write,
   forging cross-step dataflow.

## The fix

### (A) Cross-row value binding — both chips, degree 2

`#[mask_next_row]` is on `PrevValue` (and on `RegAddr`/`Address`, `Ts0`/
`Timestamp`, `IsPadding` — needed for the sortedness reads below), and
`IsSame{Reg,Addr}Next` is a **bound boolean** `key_same` (= "next row is real and
same key"). Constraint (evaluated at row i, reading row i+1):

```
key_same · (prev_value_next[k] − value_cur[k]) = 0      for each value byte k
```

Honest-consistent: the filler sets `prev_value = previous row's value` for ALL
rows (reads AND writes), so binding it everywhere is fine; the
read-consistency (`is_read·(value−prev_value)`) then chains value through reads.

### (B) Sortedness — both chips, via SELF-CONTAINED bit-decomposition

**Why not Range256:** the consumer pass runs in PARALLEL with an immutable
`&SideNote` (`prove.rs:634`), so the ledger chips CANNOT bump `range256_counts`
— only producers (CpuChip) can. So the shared Range256 table is unusable here.
It uses **boolean bit-decomposition** (no lookup, no cross-chip multiplicity):
decompose the ordering delta into N bits, constrain each `bit·(bit−1)=0` and
`Σ bits·2^i == delta`.

Bind `key_same` + sortedness together (no inverse hint needed):

```
both_real   = (1 − is_pad_cur) · (1 − is_pad_next)            # deg 2; =0 on padding boundaries AND the cyclic last→row0 wraparound (last row is padding)
key_diff    = key_val_next − key_val_cur                       # reg: single limb (faithful); MEM: see (B-mem)
key_same boolean:        key_same·(key_same−1) = 0
key_same ⇒ keys equal:   key_same · key_diff = 0
key_same ⇒ both real:    key_same · (1 − both_real) = 0        # deg 3 — flattened, see Degree
order_val   = key_same·ts_diff + (1−key_same)·(key_diff − 1)   # ts_diff = ts_next − ts_cur (combine_le)
order_delta = both_real · order_val                            # =0 off real→real transitions
Σ bits·2^i == order_delta ;  each bit boolean                  # 28 bits: ts_diff<100M, key_diff−1<13
```

- `key_same=1` ⇒ ts non-decreasing (order_val = ts_diff ≥ 0).
- `key_same=0` ⇒ order_val = key_diff−1 ≥ 0 ⇒ key strictly increases ⇒ keys are
  CONTIGUOUS (no value-chain bleed between keys) AND `key_same` is forced
  truthful (claiming 0 on equal keys gives −1, which has no 28-bit decomposition
  since a field-wrapped negative ≈ p−small ≈ 2^31 needs 31 bits → rejected).
- **28-bit bound is load-bearing**: it must remain comfortably below the M31
  modulus so a wrapped negative cannot alias a valid small positive. The
  canonical actor-proof budget admits fewer than 100M steps, which is `< 2^27`;
  register/address deltas are smaller still.

**Degree:** `both_real·key_same·ts_diff` is degree 4. These chips keep
`LOG_CONSTRAINT_DEGREE_BOUND` at 1, so the products are flattened through
helper witness columns to degree ≤ 2 (above).

**(B-mem) Memory key = u32 address > p:** `combine_le(addr[4])` WRAPS, so a
single field `key_diff` is not faithful. It compares limb-wise: split into two 16-bit
halves `a_lo,a_hi (< 2^16 < p, faithful)` and do a 2-level lexicographic compare
(`hi` first, then `lo`), each half's diff via the same bit-decomposition gadget.
~2× the register gadget's columns. (Register key = `reg_addr` single limb < 13,
faithful → simple.)

### (C) Bind `is_write` on the register ledger

The register tuple is `(reg[1], value[8], ts[8], is_write[1])`, as the RAM
tuple carries `is_write`. Every emitter, the consumer and the verifier's
recompute push it:

- **CpuChip** (prover and AIR) — `0` for the ValB/ValD/ValA/blake2b
  reads, `1` for the Result write;
- **`RegisterMemoryBoundaryChip`** — the initial-state producer:
  `is_write = 1` (ts=0 writes);
- **`RegisterMemoryClosingChip`** — the closing producer: `is_write = 0`
  (closing reads);
- **`RegisterMemoryChip`** (consumer) — its `IsWrite` column;
- **`src/boundary_binding.rs`** — `expected_register_file_sum` takes
  `is_write`: 1 for the boundary chip, 0 for the closing chip.

The ledger's `IsWrite` column is filled from `entry.is_write`
(`build_entries_from_side_note`: initial_regs→write, CpuChip reads→read,
result→write, closing→read), so it matches the producers — carrying it in
the tuple makes the balance BIND it.

### (D) One access a row (no read merge)

The register ledger holds one access a row, structurally identical to
memory's. Merging consecutive same-(reg, value) reads into multi-slot rows
would make sortedness subtle (a merged read-run spanning a write; per-slot
ts monotonicity; ts-last selection). The larger ledger costs little: the
register ledger is not a segment's dominant cost.

A merge, if one is ever designed: consecutive same-(reg, value) reads fold into
rows of up to `B5_MERGE_CAP = 4` slots (even, for `finalize_logup_in_pairs`; the
canonical bench's 29,280 rows at 4 fit log size 15). Writes never merge, and a
run longer than the cap splits into adjacent merged rows. The merge must be
deterministic and invertible (`unmerge(merge(e)) == e` for every (reg,
ts)-sorted `e`). Each merged row carries `Mult ∈ 0..=4`, `SlotReal_i = (Mult >
i)` and a timestamp `TS_i` per slot, each slot consuming `−SlotReal_i ·
(RegAddr, Value, TS_i)`, the sort key `(RegAddr, TS_0)`. It needs per-slot
ordering and a link to the next row: a slot a prover may light consumes any
read at its `Ts_i`, unordered and unchained.

**Chain start.** The adjacent-real-rows gadget alone is switched off by
padding, so rows after a padding row could form a second, unordered chain
for a register whose first row took a free `PrevValue`. A chain of
same-register rows starts at its register's `ts = 0` write (the
`ChainStartH` helper: a row whose predecessor is no same-register real row
is a write at `ts = 0`), and a register has exactly one, from the boundary
chip. Memory's address groups follow the same rule (each starts at its
page's ts = 0 write, `memory-merkle-binding.md` §2). Within a timestamp a
register's reads sort before its writes, so a step cannot read its own
result.
