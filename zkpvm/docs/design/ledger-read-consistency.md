# Ledger read-consistency soundness fix (register + RAM)

**Status:** LANDED (format v6). Both ledgers fixed — register
(`fix(zkpvm): bind register-ledger read-consistency`) and RAM
(`fix(zkpvm): bind RAM-ledger read-consistency`). The gate tests
(`tests/ledger_readconsistency_gate.rs`) are GREEN; the segment-chain
capstone re-prove validates the full ~7.5M-step workload against the new AIR.
This was the **#1 money-path soundness task** on branch
`voucher-state-transition` — the column→trace half of the v5 boundary
public-input binding, without which `final_state.registers` (and hence the
voucher io-hash in φ[9..13]) was forgeable by a from-scratch prover.

The implementation differs from the original design below in three ways worth
noting: (1) the sortedness range-check uses self-contained **boolean
bit-decomposition**, not Range256 (the consumer pass runs with an immutable
`&SideNote` and cannot bump multiplicities); (2) `LOG_CONSTRAINT_DEGREE_BOUND`
was NOT raised — the prover rejects any value > 1 on these chips, so the gadget
is flattened to degree ≤ 2 with helper columns (register: `BothRealH` +
`OrderValH`; RAM: `AdvLoH` + `AdvHiH` for the 16-bit-half lexicographic address
compare); (3) a `≥ 1 padding row` guarantee makes the cyclic last→row-0
wraparound always a padding transition, so the gadget never fires across it.

Original design (for reference):

## The gap (empirically confirmed)

`RegisterMemoryChip` (`src/chips/register_memory.rs`) and `MemoryChip`
(`src/chips/memory.rs`) enforce read-after-write only via
`is_read · (value − prev_value) = 0`. `prev_value` is a **free** main-trace
witness column:

- No `#[mask_next_row]` ties `prev_value[i]` to the previous ledger row's
  `value[i-1]`.
- `IsSame{Reg,Addr}Next` is filled but appears in **no constraint**.
- There is **no `(key, ts)` sortedness / timestamp-monotonicity** check.

So a from-scratch prover sets a read row's `prev_value := value (= a lie L)`;
read-consistency holds (`L − L = 0`) while the *actual* previous ledger row
carries the true value `T ≠ L`. This forges any register/RAM read — including
the synthetic closing read (`RegisterMemoryClosingChip`) that pins
`final_state.registers`, hence the voucher io-hash. The honest trace **filler**
is the only thing that rejects forgeries today; the existing negative corpus
(`register_ledger_negative.rs`, `memory_negative.rs`) forges the *side-note*
then runs the honest filler, so it exercises the filler, not the constraint.

### Gate tests — `tests/ledger_readconsistency_gate.rs`

`#![cfg(feature = "debug-internals")]`, currently `#[ignore]`d (RED — remove the
ignore when the fix lands). Both build an HONEST `ComponentTrace`, tamper a
single read row's `Value` + `PrevValue` cells (bypassing the filler — exactly
what a from-scratch prover does), and assert `debug_assert_constraints` REJECTS:

- `register_forged_read_value_is_rejected`: 2-step Add (φ2 written 12@ts1, read
  12@ts2); tamper the φ2 read row Value+PrevValue → 99. ACCEPTED today.
- `memory_forged_read_value_is_rejected`: StoreIndU8 0x42→[0x1000] then
  LoadIndU8; tamper the load row Value+PrevValue → 0x99. ACCEPTED today.

Run: `cargo test -p zkpvm --features debug-internals --test
ledger_readconsistency_gate -- --ignored`. **Add two STRONGER gates with the
fix** (the current two only tamper prev_value with honest `key_same`/`is_write`,
so they would pass under a *partial* fix): (a) **reorder** — place a stale write
immediately before the closing/a read (defeats value-binding-alone; closed by
sortedness); (b) **is_write-flip** — mark the closing/a read row `is_write=1` so
read-consistency skips (defeats value+sortedness; closed by is_write tuple-bind).

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
   `< 2^24 ≪ p`, so **non-decreasing (≤)** monotonicity is SUFFICIENT (equal-ts
   collisions occur only within one step and are self-policed by
   read-consistency + the bound tuple values).
3. **is_write-flip** (mark the closing/any read `is_write=1`; read-consistency is
   gated on `is_read` so it skips → value free) → **bind `is_write`**. The
   register tuple does NOT carry `is_write` today (memory's DOES:
   `(addr[4],value[1],ts[8],is_write[1])`), so a from-scratch prover sets the
   ledger `IsWrite` column freely. Fix = add `is_write` to the register logup
   tuple (17→18 limbs), matching memory. Needed for ALL reads, not just closing:
   a normal read flipped to a write decouples its value from the last write,
   forging cross-step dataflow.

## The fix

### (A) Cross-row value binding — both chips, degree 2

Add `#[mask_next_row]` to `PrevValue` (and to `RegAddr`/`Address`, `Ts0`/
`Timestamp`, `IsPadding` — needed for the sortedness reads below). Repurpose
`IsSame{Reg,Addr}Next` as a **bound boolean** `key_same` (= "next row is real and
same key"). Constraint (evaluated at row i, reading row i+1):

```
key_same · (prev_value_next[k] − value_cur[k]) = 0      for each value byte k
```

Honest-consistent: the filler sets `prev_value = previous row's value` for ALL
rows (reads AND writes), so binding it everywhere is fine; the existing
read-consistency (`is_read·(value−prev_value)`) then chains value through reads.

### (B) Sortedness — both chips, via SELF-CONTAINED bit-decomposition

**Why not Range256:** the consumer pass runs in PARALLEL with an immutable
`&SideNote` (`prove.rs:634`), so the ledger chips CANNOT bump `range256_counts`
— only producers (CpuChip) can. So the shared Range256 table is unusable here.
Use **boolean bit-decomposition** (no lookup, no cross-chip multiplicity):
decompose the ordering delta into N bits, constrain each `bit·(bit−1)=0` and
`Σ bits·2^i == delta`.

Bind `key_same` + sortedness together (no inverse hint needed):

```
both_real   = (1 − is_pad_cur) · (1 − is_pad_next)            # deg 2; =0 on padding boundaries AND the cyclic last→row0 wraparound (last row is padding)
key_diff    = key_val_next − key_val_cur                       # reg: single limb (faithful); MEM: see (B-mem)
key_same boolean:        key_same·(key_same−1) = 0
key_same ⇒ keys equal:   key_same · key_diff = 0
key_same ⇒ both real:    key_same · (1 − both_real) = 0        # deg 3 — needs degree bump, see below
order_val   = key_same·ts_diff + (1−key_same)·(key_diff − 1)   # ts_diff = ts_next − ts_cur (combine_le)
order_delta = both_real · order_val                            # =0 off real→real transitions
Σ bits·2^i == order_delta ;  each bit boolean                  # 24 bits: ts_diff<2^24, key_diff−1<13
```

- `key_same=1` ⇒ ts non-decreasing (order_val = ts_diff ≥ 0).
- `key_same=0` ⇒ order_val = key_diff−1 ≥ 0 ⇒ key strictly increases ⇒ keys are
  CONTIGUOUS (no value-chain bleed between keys) AND `key_same` is forced
  truthful (claiming 0 on equal keys gives −1, which has no 24-bit decomposition
  since a field-wrapped negative ≈ p−small ≈ 2^31 needs 31 bits → rejected).
- **24-bit bound is load-bearing**: it must be `< 2^30 < p` so a wrapped negative
  can't alias a valid small positive. ts/reg deltas are `< 2^24` ✓.

**Degree:** `both_real·key_same·ts_diff` is degree 4. Cleanest is to **bump
`LOG_CONSTRAINT_DEGREE_BOUND` 1→2** on these two chips (degree ≤ 4 fits
production blowup 16 = 2^4; no chip does this today but the framework supports a
per-component const and CpuChip's CONSTRAINTS.md notes it once used 2). This
avoids ~dozens of degree-flattening helper columns and keeps the gadget
auditable. Alternative (keep bound=1): flatten via witness columns for the
products — more columns, higher bug risk; NOT recommended for a soundness fix.

**(B-mem) Memory key = u32 address > p:** `combine_le(addr[4])` WRAPS, so a
single field `key_diff` is not faithful. Compare limb-wise: split into two 16-bit
halves `a_lo,a_hi (< 2^16 < p, faithful)` and do a 2-level lexicographic compare
(`hi` first, then `lo`), each half's diff via the same bit-decomposition gadget.
~2× the register gadget's columns. (Register key = `reg_addr` single limb < 13,
faithful → simple.)

### (C) Bind `is_write` on the register ledger — tuple 17→18 limbs

Append `is_write` to the register tuple `(reg[1], value[8], ts[8], is_write[1])`.
Every emitter + the consumer + the verifier recompute must push it:

- **`src/chips/cpu/interaction.rs`** (prover) — 5 reg emissions at lines 303,
  317, 334 (ValA ×2 in one block), 346, 374: push `0` for ValB/ValD/ValA/blake2b
  reads, `1` for the Result write.
- **`src/chips/cpu/mod.rs`** (AIR) — mirror sites at ~1858 (ValB→0), ~1874
  (ValD→0), ~1897+1902 (ValA ×2→0), ~2002 (Result→1), ~2041 (blake2b reads→0).
- **`src/chips/register_memory_boundary.rs`** — the initial-state producer:
  `is_write = 1` (ts=0 writes).
- **`src/chips/register_memory_closing.rs`** — the closing producer:
  `is_write = 0` (closing reads). Both AIR + `generate_interaction_trace`
  (`add_to_relation_computed`, bump tuple width 17→18).
- **`src/chips/register_memory.rs`** (consumer) — push the chip's `IsWrite`
  column into each of the 4 slot tuples (AIR + interaction).
- **`src/boundary_binding.rs`** — `expected_register_file_sum` takes an
  `is_write: u64` param; tuple becomes 18 limbs with `is_write` appended.
  `RegisterMemoryBoundaryChip` call passes 1, `RegisterMemoryClosingChip` passes
  0. (Memory ledger already has `is_write` in-tuple → no producer change.)

The ledger's `IsWrite` column is filled from `entry.is_write`
(`build_entries_from_side_note`: initial_regs→write, CpuChip reads→read,
result→write, closing→read), so it already matches the producers — adding it to
the tuple makes the balance BIND it.

### (D) Disable the B5 merge (register ledger)

`RegisterMemoryChip` merges consecutive same-(reg,value) READS into rows of up to
4 ts slots (`B5_MERGE_CAP`). Merged rows make sortedness subtle (overlap exploit:
a merged read-run spanning a write; per-slot ts monotonicity; ts-last selection).
**Disable it** for a clean, auditable one-entry-per-row ledger structurally
identical to memory: in `generate_main_trace_immut`, iterate `entries` (skip
`merge_entries`), set `mult=1`, `Ts0=entry.ts`, `Ts1..3=0`, `SlotReal1..3=false`.
The 4-slot emission machinery stays dormant (slots 1..3 emit 0-mult) so
`finalize_logup_in_pairs` is unchanged. `merge_entries` + its property tests stay
(uncalled). Perf cost (larger register ledger) is acceptable for a money-path fix
— the capstone is segmented and the register ledger is not the dominant cost.
[Reconsider only if profiling shows the register ledger dominates a segment.]

### (E) Format bump + docs

- `src/proof.rs`: `PROOF_FORMAT_VERSION 5 → 6` + a history entry (the AIR changed:
  new columns + the 18-limb register tuple). Verifier rejects v5 proofs.
- Do BOTH register AND memory AIR changes BEFORE the single capstone re-prove
  (avoid double-prove).
- Flip overstated caveats to "bound": `SECURITY.md` (Register/Memory consistency
  bullets), `docs/status.md` ("Open soundness gaps"),
  `register_memory_closing.rs` LIMITATION comment, `boundary_binding.rs` SCOPE
  comment, `roadmap.md` "Soundness prerequisite #1"
  register bullet, and the v5/v6 `proof.rs` history register note. Update the
  `tests/boundary_binding.rs` scope note.

## Validation

1. Gate tests flip GREEN (un-ignore); add the reorder + is_write-flip gates.
2. Fast regressions: `zkpvm --lib`, `chip_isolated`, `alu_negative`,
   `register_ledger_negative`, `memory`, `memory_negative`, `phase2_alu`,
   `voucher_check_smoke`.
3. A small full prove/verify (`register_ledger_negative::*_positive_smoke`,
   `memory_negative::*_positive_smoke`) — validates CpuChip↔ledger logup balance
   with the new 18-limb register tuple + boundary_binding end-to-end (seconds).
4. Capstone re-prove (AIR changed): `prove_transition_segmented_chain` (~90 min,
   box QUIET — OOM'd 62 GB before; keep the box quiet). Then rebuild actor ELFs
   (`just build-voucher-check` etc.) + `cargo build -p prover-extension` (cdylib)
   before any federation e2e.

## Gotchas

cipher-clerk has NO rustfmt.toml (never `cargo fmt` tree-wide there). vos hooks
fail on flaky master tests (`--no-verify`, keep YOUR files fmt-clean). Delete
`/tmp/transition_witness.bin` after any witness-layout change. NEVER add
Co-Authored-By. vos commits stay local unless asked.
