# zkpvm — perf roadmap (post-Phase-J, pre-release)

Self-contained plan for the next wave of performance work, structured
into discrete sessions a fresh agent can pick up cold.  Each item lists
*current cost*, *concrete change*, *file references*, *validation
criteria*, and *risk* so the next session doesn't need conversation
context from the migration sessions.

## Current state — Session 1 complete (2026-05-07)

| Config   | Entry point     | Prove   | Proof   | Verify | Δ vs roadmap-start |
|---       |---              |---      |---      |---     |---                 |
| STANDARD | `prove()`       | 1.40 s  | 932 KB  | 45 ms  | unchanged          |
| MOBILE   | `prove_mobile()`| **0.64 s** | 1.5 MB | 28 ms | −10% (0.71 → 0.64) |

Session-1 deliverables landed:
- 1.2 — parallel `generate_component_trace` (`56b1508`).  Producer/consumer split mirrors interaction-gen.  Saves ~6 ms trace_gen on MOBILE; sets up cleaner plumbing for the Session-3 chip-shrink work.
- 1.1 — PGO bench refresh (`55cbe3b`).  `scripts/build-pgo.sh` trains on Add log10/12/14 + clerk-private-pay-bench-mobile.  MOBILE trace_gen 124 → 85 ms; total 698 → 639 ms.  STANDARD shape isn't trained (low-cost follow-up: add a STANDARD pass to the PGO script if STANDARD prove latency matters).

Original roadmap-start state (for reference):

| Config   | Entry point     | Prove   | Proof   | Verify | vs 0790eba baseline |
|---       |---              |---      |---      |---     |---                  |
| STANDARD | `prove()`       | 1.40 s  | 932 KB  | 45 ms  | 2.75× faster        |
| MOBILE   | `prove_mobile()`| 0.71 s  | 1.5 MB  | 28 ms  | 5.4× faster         |

Stage breakdown at MOBILE (median trial; FRI is the new dominant cost):

| Stage              | Time    | %    |
|---                 |---      |---   |
| trace_gen          | 130 ms  | 19%  |
| preprocess_commit  |   6 ms  |  1%  |
| main_commit        | 175 ms  | 25%  |
| interaction_gen    |  80 ms  | 11%  |
| interaction_commit |  50 ms  |  7%  |
| FRI prove          | 270 ms  | 38%  |
| **total**          | **710 ms** | **100%** |

Trace shape: 19 active chips on tap-to-pay; main_cols 4501;
log_sizes max=16 (MemoryChip + RegisterMemoryChip).

The 1-second target is hit with margin.  The roadmap below targets
~0.5 s MOBILE (or sub-300 ms with the largest wins, *if* they pencil
out under audit).

## Session plan

Three sessions, each scoped to fit a focused dev block.  Items are
ordered by ROI / risk / dependency.  Skip ahead freely — no
inter-session dependencies except where called out.

| Session | Items | ROI | Risk |
|---      |---    |---  |---   |
| **1 — Operational + parallel-trace** | PGO build, parallel `generate_component_trace` | 25-30% combined | Low (PGO) / Medium (parallel) |
| **2 — Ristretto fixed-base** | C8 comb-method for G/H | 20-30% on tap-to-pay; bigger as payments scale | Medium (chip surgery) |
| **3 — Big chip shrinks** | B5 RegMemory log→15, B6 Memory log→15 | 15-25% (largest single wins) | High (audit-sensitive) |

Plus optional **C7 NAF-w4** as a Session 2.5 if variable-base
scalar-mults appear in any production workload.

## Cross-session conventions

* Bench harness: `cargo test -p zkpvm --release --test prove_vos_actor profile_clerk_private_pay_bench{,_mobile} -- --exact --nocapture`.  Run 5 trials, take median.  First trial is a thermal cold-start outlier — discard.
* Test gates: `cargo test -p zkpvm --test phase2_alu` (93 tests, ~4 min) AND `cargo test -p zkpvm --test chip_isolated` (3 tests, ~1 s).  Both must stay 100% green after every batch.
* Debug helper: when a constraint fails with `ConstraintsNotSatisfied`, re-run with `--features debug-internals` and call `zkpvm::debug_assert_constraints_explicit(side_note, components)` from a `#[test]`.  Combined with `CPU_EXPR_DUMP=1` env var, this gives a row-#X / constraint-#Y pinpoint plus the symbolic form of the failing constraint.  See `crates/zkpvm/tests/chip_isolated.rs::harness_cpuchip_debug_add64` for the pattern.
* Commit cadence: one commit per logical batch with bench numbers in the message.  Co-author trailer: `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`.

---

# Session 1 — Operational + parallel-trace — DONE (2026-05-07)

## Item 1.1 — Run PGO — DONE (`55cbe3b`, follow-up `d10eb1e`)

* Re-ran `scripts/build-pgo.sh` on the post-parallel-trace tip.
* MOBILE: 698 → 639 ms (~9% win, mostly from trace_gen 124 → 85 ms).
* STANDARD: 1.34 → 1.40 s post-PGO with MOBILE-only training (the
  identified follow-up).  Closed in `d10eb1e` by also training on
  `profile_clerk_private_pay_bench` (non-mobile).  Re-run
  `scripts/build-pgo.sh` to pick up both shapes.
* The −18% historical projection didn't fully materialize — likely
  because the parallel-trace + parallel-interaction paths are
  harder for PGO to specialize across thread variants.

## Item 1.2 — Parallelize `generate_component_trace` — DONE (`56b1508`)

* Producer/consumer split landed.  `IS_PRODUCER` defaults to `true` on `BuiltInProverComponent`; only `CpuChip` and `Blake2bChip` keep it.  17 consumer chips moved to `generate_main_trace_immut(&SideNote)` and the default `generate_main_trace` forwards.
* `prove_impl_with_components` runs producers sequentially, then fans consumers across rayon with shared `&SideNote`.
* Measured saving smaller than projected (130 → 124 ms on MOBILE pre-PGO; 124 → 85 ms post-PGO).  CpuChip dominates trace_gen wall-clock and stays in the sequential producer pass — the parallel pass only saves the ~30 ms of consumer-chip work.
* Useful side benefit: clean trait-level distinction between producers and consumers.  Session-3 chip-shrink work (RegisterMemoryChip, MemoryChip) operates on consumers; the immut signature constrains the surface.

(Original plan retained below for archival reference.)

* **Cost addressed**: `trace_gen` at MOBILE is 19% of prove time (~130 ms), single-threaded today.  Parallel-interaction-gen already landed (`prove.rs` interaction-gen block uses `rayon::par_iter`); this is the same idea on the trace-gen side.

* **The complication**: `BuiltInProverComponent::generate_main_trace(&mut SideNote)` takes `&mut SideNote` because some chips (the *producers*) write counts/entries that downstream *consumer* chips read in their own trace fill.

* **The pattern** (proven by interaction-gen at `prove.rs:382-413`): split into a sequential producer pass + a parallel consumer pass.

* **Concrete file references**:
  * Sequential loop today: `crates/zkpvm/src/prove.rs` ~line 280 (`let traces: Vec<ComponentTrace> = components.iter().map(|c| c.generate_component_trace(side_note)).collect();`).
  * Producer mutations to side_note (grep already done — see below).
  * Consumer reads from side_note.

* **Producer chips** (mutate `side_note` during `generate_main_trace`):
  * `CpuChip` (`crates/zkpvm/src/chips/cpu/trace_fill.rs`) — biggest producer.  Writes: `program_memory_counts`, `power_of_two_counts`, `bitwise_entries`, `compare_entries`, `mul_entries`, `divrem_entries`, `bitwise_and_counts`, `jump_table_counts`, `popcount_counts`, `bitcount_counts`, `byte_to_bits_counts`.
  * `Blake2bChip` — likely writes `bitwise_and_counts` for nibble lookups; verify with grep.
  * `RistrettoChip` — likely writes `range_check_counts` or similar; verify with grep.

* **Consumer chips** (read-only from `&SideNote`):
  * `BitwiseLookupChip`, `BitwiseChip`, `CompareChip`, `MulChip`, `DivRemChip`, `PopcountChip`, `BitcountChip`, `ByteToBitsChip`, `PowerOfTwoChip`, `ProgramMemoryChip`, `JumpTableChip`, `RangeMultiplicity256`.
  * Boundary chips (`MemoryBoundaryChip`, `RegisterMemoryBoundaryChip`, `ProgramBoundaryChip`) — likely read-only; verify.

* **Implementation steps**:
  1. Add `const IS_PRODUCER: bool = true;` (default true for safety) to `BuiltInProverComponent`.  Override `false` on confirmed-pure-consumer chips (run a grep over each chip's `generate_main_trace` body for any `side_note.X = ` / `.push` / `.entry` / `.insert` pattern; `false` only if grep is empty).
  2. Refactor `prove_impl_with_components` trace-gen pass:
     ```rust
     let (producers, consumers): (Vec<_>, Vec<_>) =
         components.iter().enumerate()
             .partition(|(_, c)| c.is_producer());
     // Pass 1: sequential, mutates side_note.
     let mut producer_traces: Vec<(usize, ComponentTrace)> = producers
         .iter().map(|(i, c)| (*i, c.generate_component_trace(side_note))).collect();
     // Pass 2: parallel, &SideNote shared immutable.
     use rayon::prelude::*;
     let mut consumer_traces: Vec<(usize, ComponentTrace)> = consumers
         .par_iter().map(|(i, c)| {
             // need a `generate_component_trace_immut(&self, &SideNote)` variant
             (*i, c.generate_component_trace_immut(side_note))
         }).collect();
     // Stitch back to the original component order.
     let mut traces: Vec<ComponentTrace> = vec![ComponentTrace::default(); components.len()];
     for (i, t) in producer_traces.drain(..) { traces[i] = t; }
     for (i, t) in consumer_traces.drain(..) { traces[i] = t; }
     ```
  3. Add `fn generate_component_trace_immut(&self, &SideNote) -> ComponentTrace` to `MachineProverComponent`.  Default impl: panic, force consumer chips to override.  Or, simpler: add a separate trait `PureConsumerComponent` that requires the immut version, and use that for the parallel pass.

* **Audit considerations**: re-running a chip's trace_fill twice (because of edition refactors) could cause subtle bugs — make sure the producer pass runs *exactly once*.  Watch for chips that *both* read and write side_note (unsafe to parallelize).

* **Validation**:
  * `phase2_alu` 93/93 GREEN
  * `chip_isolated` 3/3 GREEN
  * Bench: MOBILE expected 0.71 → ~0.62 s (saving ~50–70 ms of trace_gen via parallelism).  STANDARD: ~1.40 → ~1.32 s.

* **Risk**: medium.  Producer/consumer mis-classification → incorrect trace → constraint failure.  But constraint failures are caught by the existing test gates, so the risk is "spot the bug during dev", not "ship a soundness hole".

* **Effort estimate**: 2–3 days including audit + bench.

---

# Session 2 — Ristretto fixed-base scalar-mult

Estimated wall-clock: 3–7 days.  Producer side fully landed
(`91fa0d6`, `4efa343`, `0394ec2`); only the consumer-side chip
integration remains.

## Item 2.1 — C8: comb method for fixed bases (G and H)

* **Step 1 — DONE (`91fa0d6`)**: host-side `comb_table.rs` module, Ed25519 basepoint constants, `scalar_mult_via_comb` reference, 6 unit tests cross-checking against `point::scalar_mult_rows` for fixed + 5 random scalars.
* **Step 7 + ECALL detection — DONE (`4efa343`)**: `ScalarMultKind { Variable, FixedBasepoint }` on `RistrettoRecord`, set at ECALL handler from `detect_scalar_mult_kind` (compares against `RISTRETTO_BASEPOINT_COMPRESSED`).
* **Steps 3, 4, 6 — DONE (`0394ec2`)**: `RistrettoCombLookupElements` 130-limb relation; `RistrettoCombTableChip` with preprocessed table (1024 rows × 130 cols, filled from `comb_table::CombTable::from_base(&G)`); `Multiplicity` main column read from `side_note.ristretto_comb_counts`; chip-isolated harness pair (zero-mult succeeds, non-zero rejects open-chain).
* **Step 5 (chip-isolated POC) — DONE (`e2dfcba`, Path B)**: `RistrettoFixedBaseConsumerChip` (sibling chip per the Path-B recommendation).  Per scalar-mult call: 64 lookup rows × `(IsReal, WindowIdx, ScalarWindow, X, Y, Z, T)`, emitting +IsReal to `RistrettoCombLookupElements` with the looked-up entry.  Side-note plumbing: `RistrettoCombCall { scalar: [u8; 32] }` + `populate_ristretto_comb_counts` walking each call's 64 windows.  New chip-isolated harness `harness_ristretto_comb_balance` proves `[table, consumer]` together; relation closes end-to-end and verify accepts.
* **Step 5 (running sum) — DONE (`b1856f0`)**: `RistrettoFixedBaseConsumerChip` extended to lay out `3 boundary inputs + 64 × (1 lookup-anchor + 3 lookup-coord + 18 FieldOp add) = 1411 rows per call`.  Soundness chain: comb relation (130-limb), anchor X-coord per-row binding, anchor Y/Z/T cross-row binding via new `RistrettoCombConsumerRegisterFileLookupElements`, FieldOp algebra via shared `add_field_op_constraints` helper, source-row threading via `point_add_rows_chained`.  Bug fix during integration: `eval.finalize_logup()` only matches `LogupTraceBuilder`'s pairing on 1-emission-per-row chips; the 193-emission consumer chip switched to `finalize_logup_in_pairs`.  Validation: chip_isolated 8/8 + phase2_alu 94/94 GREEN.

### Running-sum row layout (next-session implementation guide)

**Per scalar-mult call** (~1412 rows; log_size 13 for 4 calls):
- `~3` boundary input rows for constants (zero, one, ED25519_TWO_D).
- `64 × 22 = 1408` window rows (4 lookup-input + 18 FieldOp add rows per window).
- `1` boundary output row tying final Acc to ECALL output (see step 8).

**Per window (22 rows = 4 lookup-input + 18 add)**:

| Offset | Class | IsInput | IsLookupAnchor | `out` | Other columns | Emissions |
|---:|:--|:-:|:-:|:--|:--|:--|
| `+0` | lookup-anchor | 1 | 1 | `T[i][k_i].x` | WindowIdx=i, ScalarWindow=k_i, `X=out`, `Y=…y`, `Z=…z`, `T=…t` | +1 to `RistrettoCombLookupElements`; +1 producer to chip-local register-file (key: row_id, byte_idx, X[byte_idx]); 3 *consumer* tuples on chip-local register-file binding `Y/Z/T` columns to rows `+1/+2/+3`'s `out`. |
| `+1..+3` | lookup-coord | 1 | 0 | `T[i][k_i].y/z/t` | — | +1 producer to chip-local register-file. |
| `+4..+21` | FieldOp add | (no — is_add/is_sub/is_mul) | 0 | per `point_add_rows` (point.rs:139) | a, b, out, carry chains, source rows | FieldOp algebra (via shared `add_field_op_constraints`); register-file producer/consumer tuples for inter-row binding. |

**Source-row threading** (chip-local, 16-bit row IDs, fits log_size ≤ 16):
- The 18 FieldOp add rows for window `i` use:
  - `(p.x, p.y, p.z, p.t)` → previous window's final Acc add rows (4 specific row IDs from window `i-1`'s add chain, or boundary input rows for `i = 0` / identity).
  - `(q.x, q.y, q.z, q.t)` → window `i`'s rows `+0..+3` (the lookup-coord rows).
- The first window seeds `acc = identity`; identity's coords come from the boundary input rows for zero (`acc.x = acc.t = 0`) and one (`acc.y = acc.z = 1`).

**Soundness of lookup-anchor's Y/Z/T binding**: row `+0` holds `Y, Z, T` in dedicated witness columns whose values must match rows `+1..+3`'s `out`s.  Cross-row reads aren't directly expressible in Stwo's `add_constraints`, so we close the gap via the chip-local register-file relation:
- Row `+0` emits *consumer* tuples `(row_+1_id, byte_idx, Y[byte_idx])` for byte_idx ∈ 0..32 (likewise for Z/T sourcing from `+2`/`+3`).
- Rows `+1`/`+2`/`+3` emit *producer* tuples `(self_row_id, byte_idx, out[byte_idx])`.
- Balance forces `Y == out_at_+1`, `Z == out_at_+2`, `T == out_at_+3`.
- Row `+0`'s own `X == out` is a per-row constraint (no relation needed).

**Lookup-anchor's emission to `RistrettoCombLookupElements`** uses `(WindowIdx, ScalarWindow, X, Y, Z, T)` from the row's own columns — the relation balance against `RistrettoCombTableChip` then forces these to equal the preprocessed table's `T[i][k_i]`.

**Step 8 (ECALL boundary binding)** ties the consumer chip into RistrettoEcallChip's existing scalar/output byte boundary:
- Add a new `RistrettoCombBoundaryLookupElements` relation with tuple `(call_idx, kind ∈ {scalar, output}, byte_idx, value)`.
- Consumer chip emits `+1` per scalar/output byte on its first/last input rows respectively (32 bytes each per call × `n_calls` × 2 sides).
- RistrettoEcallChip emits `−1` on the matching scalar/output bytes for `ScalarMultKind::FixedBasepoint` records.
- Side-note plumbing: branch on `rec.kind` in `ingest_ristretto_boundary`; populate `ristretto_comb_calls` for fixed-base records.

**Activity gating**: add `ChipActivity.ristretto_comb` (true iff `!side_note.ristretto_comb_calls.is_empty()`); gate `RistrettoCombTableChip` and `RistrettoFixedBaseConsumerChip` on it in `BASE_COMPONENTS`; mirror in `is_active`.
* **Step 8 — DONE for scalar binding (`af777d6` + `02922c4` register fix + `005dc59` nibble binding + `82f893d` memory binding + `0218a41` e2e harness); output binding still open (R1e-bis)**: `ingest_ristretto_boundary` branches on `rec.kind` — `FixedBasepoint` records route to `ristretto_comb_calls` and skip RistrettoChip's boundary rows; `Variable` records continue through the existing 6-row block.  `populate_ristretto_comb_counts` is called inline (idempotent: zeroes counts before walking).  Production traces NOW activate the comb path: clerk-private-pay-bench classifies 5/7 records as `FixedBasepoint`, routes them through the comb chips, and proves+verifies cleanly.

  **Register-mapping bug found and fixed (`02922c4`)**: the host's tracing handler for `ECALL_RISTRETTO_SCALAR_MULT` was reading PVM φ[10/11/12] expecting RISC-V `a0/a1/a2` — but grey-transpiler's `map_register` routes RISC-V x10/x11/x12 → PVM φ[7/8/9] (φ[10/11/12] are a3/a4/a5).  For transpiled actor traces, scalar_ptr/point_ptr/output_ptr were silently 0/0/65 (= VOS_OBJECT_CAP), so the host read junk bytes from PVM memory at address 0 and `detect_scalar_mult_kind` never matched the basepoint.  Fix: read φ[7/8/9] in the scalar_mult handler and update `harness_ristretto_isolated` to put pointers in regs[7/8/9].  **All other ECALL handlers carrying the same off-by-three are now also fixed**: `5339d38` (scalar_reduce_wide), `1cc1296` (scalar_binop), `8c3a9ff` (point_add), and `7d20d4c` (blake2b — the most involved, since it required coordinated changes across `cpu/{trace_fill,mod,interaction,reg_access}.rs` to flip slot-to-register mappings for the `Blake2bCallLookupElements` tuple).  Pre-existing PcsPolicy floor failures on `prove_blake2b_via_ecall` and `prove_blake2b_precompile` (test-only) were also fixed in `7d20d4c` by switching to `verify_with_pcs_policy` with a permissive policy.

  **Soundness binding** — scalar fully closed (commits `005dc59`,
  `82f893d`, `0218a41`):
  - **Scalar nibbles ↔ side_note.scalar** (commit `005dc59`): NEW
    `RistrettoCombScalarBoundaryLookupElements` (3-limb tuple,
    `(call, window, k_value)`) bound between the anchor chip's
    +IsReal emission per row and a new
    `RistrettoCombScalarBoundaryChip` that reads the actor's scalar
    bytes from `ristretto_comb_calls` and decomposes them into
    nibbles.  Balance forces `ScalarWindow` per (call, window) to
    match the actor's i-th nibble.
  - **side_note ↔ PVM memory** (commits `82f893d` + `0218a41`): DONE.
    `kind: ScalarMultKind` added to `RistrettoMemOp`;
    `RistrettoEcallChip::collect_accesses` skips the 32-byte scalar
    block when `op.kind == FixedBasepoint`;
    `RistrettoCombScalarBoundaryChip` rebuilt at 32 rows/call
    (was 64) carrying `(IsReal, CallIdx, LowNibble, HighNibble,
    ScalarByte, Addr[4], Ts[8])` plus two preprocessed window-index
    columns.  Per-row constraint `IsReal · (ScalarByte − LowNibble
    − 16·HighNibble) = 0` ties the byte to its decomposition; 2
    −IsReal scalar-boundary emissions drain the anchor's per-window
    +IsReal; 1 +IsReal `MemoryAccessLookupElements` producer pins
    the byte to PVM memory at `(scalar_ptr + i, ts)`.  New
    `harness_ristretto_fixed_base_e2e_with_memory` exercises the
    full chain (MemoryChip + MemoryBoundaryChip + RistrettoEcallChip
    + comb chip pair); `harness_ristretto_comb_balance` flipped to
    open-chain rejection (chip's new memory producer goes
    unbalanced without MemoryChip in scope, as designed).
  - **Final Acc ↔ output bytes**: STILL OPEN.  Needs the compress
    chain (R1e-bis, ~25 FieldOp rows per call) — the bigger chunk.

  **Bench numbers** (post step 8 memory binding): ~0.76 s MOBILE
  5-trial median (trials 2–5: 782, 737, 750, 764 ms; trial 1
  cold-start 789 ms discarded).  Slight win vs the 0.79 s pre-step-8
  baseline; the EcallChip 96→64 byte shrink per fixed-base call more
  than offsets the boundary chip's +320 cells/call.  Still 8%
  slower than the 0.71 s pre-comb-chip baseline (the gap is the
  consumer chip's FieldOp add chain — output binding via R1e-bis is
  the next unlock).
* **Activity gating — DONE (`daaff55`)**: `ChipActivity.ristretto_comb` (true iff `!ristretto_comb_calls.is_empty()`) gates `RistrettoCombTableChip` (idx 21) + `RistrettoFixedBaseConsumerChip` (idx 22) in `BASE_COMPONENTS`.

### R1e-bis output binding (compress chain) — design sketch

The remaining Step 8 piece.  The consumer chip's final extended-Edwards
accumulator `Acc = (X, Y, Z, T)` (32 bytes per coord, sitting in the
last 4 add rows of the chain for the 64th window) needs to be tied to
the 32-byte compressed Ristretto encoding the actor stored at
`output_ptr`.  Today that storage is a free witness on the prover —
nothing forces it to equal `compress(Acc)`.

**Compress per dalek's reference** (curve25519-dalek source,
`ristretto.rs::compress`):

```
u1 = (Z + Y) · (Z - Y)               // mod p25519
u2 = X · Y
inv_sqrt = (u1 · u2²)^((p-3)/4)·...  // ±1/√(u1·u2²); witness + verify
i1 = inv_sqrt · u1
i2 = inv_sqrt · u2
z_inv = i1 · (i2 · T)
rotate = (T · z_inv).is_negative()
  (X, Y, den_inv) := if rotate then (Y·SQRT_M1, X·SQRT_M1,
                                     i1·INVSQRT_A_MINUS_D)
                     else        (X, Y, i2)
Y_neg = Y · sign((X · z_inv).is_negative())
s = den_inv · (Z - Y_neg)
s_can = s · sign(s.is_negative())
output = s_can.as_bytes()
```

**Row budget** (~22-25 rows per call, all reusing the existing
field_op_constraints helper):

| # | Row class                | Source bytes                  | Out                    |
|---|---                       |---                            |---                     |
|  1 | `is_add`  (Z+Y)         | Z, Y from anchor consumer      | Z+Y mod p              |
|  2 | `is_sub`  (Z-Y)         | Z, Y from anchor consumer      | Z-Y mod p              |
|  3 | `is_mul`  u1            | rows 1, 2                      | u1                     |
|  4 | `is_mul`  u2            | X, Y from anchor consumer      | u2                     |
|  5 | `is_mul`  u2sq          | row 4, row 4                   | u2²                    |
|  6 | `is_mul`  u1·u2sq       | rows 3, 5                      | tmp                    |
|  7 | `is_mul`  inv_sqrt²     | inv_sqrt witness × itself      | should be ±tmp⁻¹       |
|  8 | `is_mul`  inv_sqrt²·tmp | row 7, row 6                   | should be ±1           |
|  9 | `is_mul`  i1            | inv_sqrt witness, row 3        | i1                     |
| 10 | `is_mul`  i2            | inv_sqrt witness, row 4        | i2                     |
| 11 | `is_mul`  i2·T          | row 10, T from anchor          | i2T                    |
| 12 | `is_mul`  z_inv         | row 9, row 11                  | z_inv                  |
| 13 | `is_mul`  T·z_inv       | T, row 12                      | for sign check         |
| 14 | sign-check               | row 13's `out` low byte         | rotate flag (witness)  |
| 15 | `is_mul`  iX            | X, SQRT_M1 const               | iX                     |
| 16 | `is_mul`  iY            | Y, SQRT_M1 const               | iY                     |
| 17 | `is_mul`  enchanted     | row 9, INVSQRT_A_MINUS_D const | enchanted_denom        |
| 18 | conditional select       | rows 16/X, 15/Y, row 10/17     | 3 selects (witness)    |
| 19 | `is_mul`  X·z_inv       | row 18 X, row 12               | for sign check         |
| 20 | sign-check               | row 19                          | y_negate flag (witness)|
| 21 | conditional negate Y     | row 18 Y                        | Y_neg (witness)        |
| 22 | `is_sub`  Z - Y_neg     | Z, Y_neg                        | Z-Y_neg                |
| 23 | `is_mul`  s             | row 18 den_inv, row 22         | s                      |
| 24 | sign-check               | row 23 byte 0 LSB               | s_neg flag             |
| 25 | conditional negate s     | row 23                          | output bytes (witness) |

**Inter-chip bindings**:

- **Consumer chip → compress chain (`X/Y/Z/T` of final Acc)**: the
  consumer chip's last 4 IsInput coord rows (corresponding to window
  63's anchor) hold X/Y/Z/T.  Compress chain rows 1-4 reference those
  via the chip-local register-file relation
  (`RistrettoCombConsumerRegisterFileLookupElements`) — same source-row
  threading mechanism the existing add chain uses for `q.{x,y,z,t}`.
  Add a sibling relation if it's cleaner to bound separately; reuse
  the existing one if the chip-local row IDs don't collide.
- **Compress chain → output bytes (PVM memory)**: row 25's `out` (32
  bytes of canonical s) is emitted as +IsReal `MemoryAccessLookupElements`
  producers at `(output_ptr+i, byte, ts, is_write=1)` for i=0..32.
  Mirrors the scalar-byte producer pattern from
  `RistrettoCombScalarBoundaryChip` (commit `82f893d`).
  `RistrettoEcallChip::collect_accesses` skips the 32-byte output
  block when `op.kind == FixedBasepoint` — same shape as the scalar
  skip already in place.

**inv_sqrt witness**: the prover provides `inv_sqrt` as a 32-byte
witness column on row 7's `a` and `b` (squaring to row 7's `out`).
Row 8 verifies `inv_sqrt² · (u1·u2²) = ±1`.  The ±1 ambiguity is
resolved by another witness bit + per-byte canonical encoding check
(every byte-0 bit-0 of result equals the sign witness; bytes 1..32
all zero).  ~3 extra constraint rows.

**Sign checks (rows 14, 20, 24)**: a Ristretto element `s` is
canonical-positive iff `s.bytes[0] & 1 == 0` (after reducing mod p).
The chip witnesses `s.bytes[0]`'s LSB via byte-to-bits decomposition
(reuse `ByteToBitsLookupElements`).  ~1 extra emission per sign check.

**Activity gating**: same `ChipActivity.ristretto_comb` flag that
gates the existing comb chip pair; the compress rows live inside the
existing `RistrettoFixedBaseConsumerChip` (extending its row layout
from `~1411` to `~1436` per call) OR in a new sibling
`RistrettoCombCompressChip` (cleaner but duplicates field-op
infrastructure).  Path A (extend consumer chip) is the smaller diff;
Path B (sibling chip) is the cleaner separation.

**Bench projection**: ~25 extra FieldOp rows per call × 5 calls ×
~50 cells/row ≈ 6 K extra cells.  Negligible (current consumer chip
is ~7 M cells at log_size=13).  Bench should stay within noise of
post-step-8 ~0.79 s MOBILE.

**Effort estimate**: 3-5 days including audit + bench.  Multi-commit;
natural batches:
1. Add inv_sqrt + output_bytes witness columns to side_note +
   consumer chip column layout.
2. Implement compress chain rows 1-12 (the algebra prologue).
3. Implement sign-checks + conditional rows.
4. Wire up output-byte memory producer + RistrettoEcallChip skip.
5. Add chip-isolated harness + bench validation.

### Step 5 design tree

The consumer side has to (a) emit one `+1` contribution to
`RistrettoCombLookupElements` per scalar-mult window, with the
130-limb tuple `(window_idx, scalar_window, x[32], y[32], z[32], t[32])`
matching the looked-up table entry, and (b) compose 64 point-adds
that accumulate the looked-up entries into the scalar-mult result,
binding the input scalar bytes (so the prover can't fake the
windows) and the output point bytes (so the chip's running sum
matches the ECALL output).

Two architectural paths to choose between, in decreasing order of
diff size and risk:

**Path A — extend `RistrettoChip` (chips/ristretto/mod.rs, 1266 LOC).**
Add an `IsFixedBaseComb` row-class flag.  Per such row:
- The 32-byte X/Y/Z/T columns hold the looked-up table entry.
- A new constraint emits `+is_fixed_base_comb` to the comb relation
  with the 130-limb tuple from this row's columns + window/scalar
  scratch columns.
- The existing `IsAdd` row class accumulates the running sum,
  source-row threaded onto the prior comb row's `out`.
- The existing register-file lookup mechanism keeps inter-row binding.

Pros: reuses existing 4501-column trace shape, source-row threading,
register-file relation.
Cons: large diff to a chip that's already complex; adds ~3 columns
(window_idx, scalar_window, IsFixedBaseComb flag); has to coexist
with the existing IsAdd/IsSub/IsMul/IsInput/IsOutput row-class
partition without breaking the boolean-1-of-N closure.

**Path B — sibling `RistrettoFixedBaseConsumerChip`.**
Independent chip with its own column layout, 64-windows-per-mult
trace shape, and constraint chain.  Receives input scalar / output
point bytes from `ingest_ristretto_boundary` via a new boundary
relation tying it to the existing RistrettoEcallChip ECALL records.

Pros: clean separation; smaller diff to RistrettoChip (zero); easier
to verify in isolation.
Cons: rewrites the point-add chain that already exists in `point.rs`;
needs a new boundary relation between this chip and
RistrettoEcallChip; two chips for "ristretto scalar mult" splits the
mental model.

**Recommendation**: start with Path B as a chip-isolated proof of
concept; if the boundary-relation overhead turns out to be acceptable,
ship it.  If Path B's bench doesn't justify the duplicated point-add
chain, fall back to Path A.

* **Why this is the right tap-to-pay win**: cipher-clerk's private-pay flow does:
  * Pedersen commit: `v · G + b · H` — 2 fixed-base scalar-mults.
  * Schnorr sign: `k · G` (nonce), `pk = sk · G` (key) — 2 more fixed-base scalar-mults.
  * **Every scalar-mult in tap-to-pay is fixed-base.**  Variable-base (`k · P` for variable `P`) doesn't appear in this flow today.  Going fixed-base is the highest-leverage Ristretto change for tap-to-pay specifically.

* **Cost addressed**: each scalar-mult today is ~256 doublings + ~128 conditional adds = ~384 point ops.  Comb method (4-bit windows × 64 windows): 0 doublings + 63 adds = **6× fewer chip rows per scalar-mult**.  Across 4 scalar-mults per payment, this could shrink RistrettoChip's log_size from log=12 → log=10 on the current 24K-step bench, and from log=17 → log=15 on full-scale projections.

* **What** (the comb method):
  * Precompute, per fixed base point `B` (G and H):
    * `T[i][j] = j · 2^(4·i) · B` for `i ∈ 0..64` (windows), `j ∈ 0..16` (4-bit values).
    * 64 × 16 = 1024 entries per base × 4 field elements = 4096 BaseField cells per base.  Two bases (G, H) = ~8 KB of preprocessed columns.  Tiny relative to the chip's existing column count.
  * Scalar mult `k · B`:
    * Split `k` (256-bit) into 64 4-bit windows: `k = Σ k_i · 2^(4·i)`.
    * Compute `k · B = Σ T[i][k_i]`.
    * Chip emits 64 table-lookup rows (one per window) + 63 add rows = 127 rows per scalar-mult vs ~6500 today.

* **Concrete file references**:
  * `crates/zkpvm/src/chips/ristretto/point.rs:515` — `pub fn scalar_mult_rows(scalar, p)`.  Today: variable-base double-and-add.  Add: `pub fn scalar_mult_rows_fixed_base(scalar, base_id)` where `base_id ∈ {G, H}` and routes through the comb table.
  * `crates/zkpvm/src/chips/ristretto/mod.rs` — chip-level constraints.  Add: a per-row table-lookup constraint that reads the preprocessed comb table at `(window_idx, k_i)` and binds the row's output to that table entry.
  * `crates/zkpvm/src/chips/ristretto_ecall.rs` — ECALL dispatch.  Detect "scalar-mult on G or H" at the side_note level and route to fixed-base witness generation; fall back to the variable-base path when the input point isn't G or H.

* **The chip-side mechanics**:
  * Stwo's preprocessed-column system handles "constant tables that the prover and verifier both compute deterministically" — see `crates/zkpvm/src/chips/range_multiplicity_256.rs` or `crates/zkpvm/src/chips/byte_to_bits.rs` for examples of preprocessed-table chips.
  * The lookup constraint: per row, the chip needs to prove `(window_idx, k_i, T[window_idx][k_i].x, .y, .z, .t)` is a row of the preprocessed table.  This is a standard Plookup-style relation, expressible via the existing `add_to_relation` machinery.
  * New `LookupElements`: `RistrettoFixedBaseLookupElements` (one relation per base point, or one shared relation indexed by base_id).

* **Implementation steps**:
  1. Define the comb-table layout in a new `crates/zkpvm/src/chips/ristretto/comb_table.rs`.  Both G and H tables generated at chip-init from `curve25519_dalek::constants::ED25519_BASEPOINT_POINT` (G) and the Ristretto255 H point (canonical hash-to-curve output).
  2. Add a `PreprocessedColumn::CombTable*` variant family to `RistrettoChip`'s preprocessed columns.
  3. Define the `RistrettoCombTableLookupElements` relation.  Tuple shape: `(base_id, window_idx, scalar_window, x_bytes..., y_bytes..., z_bytes..., t_bytes...)`.  ~36 limbs.
  4. In `scalar_mult_rows_fixed_base`: emit 64 lookup-consumer rows + 63 add rows.  Each lookup row carries `(base_id, window_idx, k_i, T[window_idx][k_i])`.
  5. In `RistrettoChip::add_constraints`: bind the lookup-row outputs to the per-row scratch columns that feed into the running sum.
  6. Producer chip (`RistrettoCombTableChip` — new): emits the table entries with their natural multiplicity (always once per (base, window, value) triple).
  7. Side-note plumbing: `ristretto_calls` get a `kind: ScalarMultKind { Variable, FixedG, FixedH }` field so the chip knows which path to take.
  8. ECALL boundary: detect that the input point bytes match G or H bytes; downgrade to variable-base if not (defensive fallback for future extensibility).

* **Validation**:
  * Add `harness_ristretto_fixed_g_isolated` and `harness_ristretto_fixed_h_isolated` to `crates/zkpvm/tests/chip_isolated.rs` mirroring the existing `harness_blake2b_isolated` pattern.  Each: prove a single `k · G` (resp. `k · H`) scalar-mult, expect open-chain rejection at verify (sink chips not in scope).
  * Cross-check witness against `curve25519_dalek::EdwardsPoint::mul_base()`.
  * Existing `prove_vos_actor::profile_clerk_private_pay_bench` should run faster *and* still verify cleanly.
  * Bench target: MOBILE 0.71 → 0.50–0.55 s (saving 150–200 ms via the chip-row reduction propagating to all stages).

* **Risk**: medium.  Soundness depends on:
  * Comb table being correctly precomputed (host-side bug → wrong proof → caught by test).
  * The lookup constraint actually binding the chip's output to the table entry (not just reading from an unconstrained witness column).
  * Detecting G/H correctly at the ECALL boundary (a malicious prover supplying `k · P` where `P` happens to byte-equal G should be fine — it IS k · G in that case).

* **Effort estimate**: 3–5 days for one base (G), +1–2 days for H if structurally similar.  Plus ~1–2 days of audit/test before merging.

## Item 2.2 (optional) — C7: NAF-w4 windowing for variable base

Skip unless production telemetry shows variable-base scalar-mults
appearing.  All current tap-to-pay flows are fixed-base, so this is
defensive future-proofing only.

* **What**: replace the 256-bit double-and-add in `scalar_mult_rows` with windowed NAF (signed-digit, width 4).  Density 1/(w+1) = 1/5 → ~51 nonzero windows × 1 add each, plus 7 precomp adds for the multiples table.
* **Cost**: ~1 week including chip-side support for negation rows and per-window table lookups.
* **Win**: ~20% Ristretto-row reduction for variable-base.  Stacks on or substitutes for C8 depending on the workload mix.

---

# Session 3 — Big chip-shrink wins (audit-sensitive)

Estimated wall-clock: 2–4 weeks per item.  Schedule one at a time.

These are the largest remaining single-item perf wins, but they touch
the soundness backbone (per-step register/memory ledger) — *do not
attempt without a parallel audit pass*.

## Item 3.1 — B5: shrink RegisterMemoryChip log=16 → 15

* **Cost addressed**: RegisterMemoryChip is one of two chips at
  log=16 (65k rows) on the canonical tap-to-pay bench.  Each PVM step
  emits ~3 register-access events (2 reads + 1 write average), so
  24K steps → ~70K events → log=17.  We currently round to log=16
  via a different mechanism (which puts us right at the boundary).
  Halving the chip's row count (log=16 → 15) frees up the largest
  single block of FRI / commit work.

* **The proposal**: deduplicate consecutive same-register reads into
  one ledger entry.  When a step reads `r1` immediately after another
  step also read `r1` (and `r1` wasn't written between), fold the
  reads into one entry with a `multiplicity` field.  PVM bytecode has
  many such patterns (e.g., consecutive `Add r1, r2, r1` instructions
  re-read r2).

* **Where**: `crates/zkpvm/src/chips/register_memory.rs::generate_main_trace` (~line 147).  The `entries: Vec<RegEntry>` builder loops over `side_note.steps` and pushes per-access entries.  Add a "merge with previous if same reg + same value" rule.

* **Constraint changes**: the AIR currently constrains "value = prev_value on reads" pairwise across consecutive entries (at the same address).  With multiplicity, the constraint becomes "value · multiplicity is consistent across the run."  Need a runs-of-equal-value invariant — Plonkish-style.

* **Risk**: HIGH.  This chip authenticates every register read in every step.  An off-by-one in the merge rule = a soundness hole.  Pair with a thorough audit pass.

* **Validation**:
  * Existing `phase2_alu` 93/93 + `chip_isolated` 3/3 GREEN.
  * Add: a property-test sweep (`tests/quickcheck_register_memory.rs` or similar) that randomly generates step sequences, builds the merged ledger, and re-derives the unmerged ledger from it — they must be byte-identical for any trace.
  * Bench target: MOBILE 0.71 → ~0.60 s.

* **Effort**: 2–3 weeks including audit.

## Item 3.2 — B6: shrink MemoryChip log=16 → 15

* **Same idea as B5 but for byte-level memory access**.  Each PVM
  step emits 1–8 byte accesses (an 8-byte load = 8 entries).  Loads
  of consecutive bytes within a single instruction are the obvious
  dedup target — replace per-byte entries with a single entry +
  size flag.

* **Risk**: HIGH for the same reason as B5 plus an additional wrinkle:
  byte vs. word boundaries.  The current decompose-to-bytes
  representation is what makes the memory check uniform; merging
  byte runs back to words requires uniformity-breaking case logic.

* **Effort**: 2–4 weeks.  Realistically should follow B5 (which
  proves the dedup pattern works on the simpler register chip).

## Item 3.3 (further future) — Plonkish-style memory check

If both 3.1 and 3.2 land, the next architectural step is replacing
both ledger chips with a single "address-space" chip that uses
logUp's running-sum machinery rather than per-event entries.
Months of work, only worth it if production payment workloads start
saturating log=18+.

---

# Out of scope (revisit later)

Items I've considered and consciously deprioritised:

* **B4: chip-local helper relocation** — moving DivRem/Mul-only helpers from CpuChip into their respective chips.  Win is small (2–5%) and only on workloads that don't exercise the relocated chip.  Tap-to-pay uses every chip already.  Revisit if a workload class emerges that's pure-ALU (no Mul/DivRem).
* **D9: GPU Merkle commit** — 2–4× speedup on commit stages but server-side win.  Mobile GPUs are weak; binary-distribution + CUDA/Metal kernel maintenance are real costs.  Wrong shape for mobile-first tap-to-pay UX.
* **D10: Different Merkle hash (Poseidon, Blake3)** — Stwo upstream isn't going to merge a non-Blake2s `MerkleChannel` soon, and Blake2s has SHA-NI on the test bench, so the win is workload-dependent.  Coordination-heavy.
* **E11: Segmented + recursive aggregation** — months of work.  Right call when single-shot payments outgrow what fits in a comfortable proof.  Not before.
* **Stwo upstream issues** — two issue drafts (`STWO_UPSTREAM_ISSUE_DRAFT.md` lifted-protocol degree-≥2 gap, `STWO_MERKLE_LIFTED_OOB_ISSUE_DRAFT.md` mixed-width Merkle OOB).  Filing deferred until the project is live and well-tested.  Neither blocks us — bound-1 flatten + chip-isolated bench shape sidesteps both.

---

# Bench cadence + measurement protocol

Every change in this roadmap should be benched before-and-after with
the same protocol so numbers are comparable across sessions:

```
# Take 5 trials each, ignore the first (cold-start outlier):
for i in 1 2 3 4 5; do
  cargo test -p zkpvm --release --test prove_vos_actor \
    profile_clerk_private_pay_bench_mobile -- --exact --nocapture \
    2>&1 | grep -E 'total:|interaction_gen|main_commit'
done
```

Same for STANDARD (`profile_clerk_private_pay_bench`).  Report median
of trials 2–5 in commit messages.  Update `BENCHMARKS.md`'s "Latest"
section after every meaningful win.

---

# Closing-out checklist (pre-release)

Once Sessions 1–2 are done (Session 3 is bonus, not required for
release):

- [ ] PGO build verified (Item 1.1)
- [ ] `cargo test -p zkpvm` 100% green
- [ ] `BENCHMARKS.md` reflects current numbers
- [ ] `STWO_2.2.0_MIGRATION.md` final-state section accurate
- [ ] Two upstream issue drafts filed *or* explicitly deferred with reason
- [ ] Public API surface review: `prove`, `prove_mobile`, `prove_with_config`, `verify`, `verify_with_pcs_policy`, `PcsPolicy::{STANDARD, MOBILE}` documented and tested
- [ ] Tap-to-pay end-to-end bench reproducible from a clean checkout
