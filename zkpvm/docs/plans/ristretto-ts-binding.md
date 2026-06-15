# Phase A prereq 0.2 — ristretto mem-op `ts` binding (design v4)

Status: **design converged + adversarially validated (2 rounds), implementation-ready.**
No code yet. Supersedes Appendix A of `memory-merkle-binding.md`.

## 1. The gap (money-path soundness)

The three ristretto-family memory producers emit `MemoryAccessLookupElements`
tuples `(addr[4], value[1], ts[8], is_write[1], is_closing[1])` whose **`ts` is a
free witness** — nothing in-AIR ties it to a genuine ECALL step:

- `RistrettoEcallChip` (`ristretto_ecall.rs`) — point reads of every call, plus
  the scalar reads + output writes of *variable-base* scalar_mult, point_add,
  scalar_reduce_wide, scalar_binop;
- `RistrettoCombScalarBoundaryChip` (`ristretto_comb_scalar_boundary.rs`) — the
  32 scalar reads of *fixed-base* scalar_mult;
- `RistrettoCombCompressOutputChip` (`ristretto_comb_compress_output.rs`) — the
  32 output writes of *fixed-base* scalar_mult.

A from-scratch prover sets a ristretto write's `ts` to **0** (collides with the
§2 per-page `ts=0` boundary write → **entry forgery**) or to **`closing_ts`**
(sorts just before the per-page closing read → **exit forgery**), or to any
in-range value to fabricate a memory state. All three chips are active on the
clerk conservation proof (cipher-clerk Schnorr + Pedersen use fixed-base mult),
so this is a money-path gap. The CpuChip step-timestamp chain (`cpu/mod.rs:143-185`,
`NextTimestamp = Timestamp + 1`, boundary-anchored) already pins every *real
step* ts into `[initial_ts, final_ts)` and reserves `0`/`closing_ts`; the fix
only has to prove **each ristretto mem-op `ts` is a genuine ristretto-ECALL step
ts**.

The ECALL ids (`core/ecall.rs`): `110` SCALAR_MULT, `111` POINT_ADD, `112`
SCALAR_FROM_BYTES_MOD_ORDER_WIDE (reduce_wide), `113` SCALAR_MUL_MOD_L, `114`
SCALAR_ADD_MOD_L (113/114 share the binop mem-op family). Scope = **all five**.

## 2. The template we mirror — blake2b `CallTs`

blake2b already solves this exact problem (`Blake2bCallLookupElements`,
`relations.rs:172`):

- **Producer** (CpuChip, `cpu/interaction.rs:405-425`, `cpu/mod.rs:2138-2145`):
  gated on `IsBlakeEcall`, emits **+1** per blake ECALL step carrying
  `(h_ptr, m_ptr, t, f, timestamp)` — `timestamp` is the chained step ts, the
  pointers are `Phi*` register-snapshot columns.
- **Pointer authentication** (`cpu/mod.rs:2080-2097`): at the same gate, CpuChip
  emits register-read producers `ECALL_REG_IDXS=[10,7,8,9]` so the snapshot
  pointers are bound to the real register file at the step ts (not self-asserted).
- **Consumer** (Blake2bChip, `blake2b/mod.rs:1191,1209-1213`): **−1** per
  compression at the init row; reuses `CallTs` as the ts limbs of its 256
  mem-op tuples and **holds it constant across the 96-row block** via
  `gate·(CallTs_next − CallTs)=0` (`mod.rs:1056-1058`).
- **InitGate is preprocessed-pinned** (`mod.rs:198`):
  `InitGateH = is_real · IsFirstOfCompression_pp` — placement is fixed by the
  96-row preprocessed period (`mod.rs:97-99,2003-2008`), not a free witness.
- **Per-byte address derivation** (`mod.rs:1077-1106`):
  `init_gate · (addr_u32 − ptr_u32 − offset) = 0` welds each mem-op address to
  the authenticated pointer + offset.

The ristretto design is this template, generalized to a flat per-byte chip with
a runtime-variable call kind.

## 3. The multiplicity problem and its resolution

`ECALL_RISTRETTO_SCALAR_MULT` (110) is **fixed-base** (RistrettoEcallChip
handles only the 32 point reads; scalar reads → CombScalarBoundary, output
writes → CombCompressOutput; consumer fan-out k=3) **or variable-base**
(RistrettoEcallChip handles all 96; k=1), decided at runtime by
`detect_scalar_mult_kind(point == basepoint)` (`tracing.rs:132-141`) which
CpuChip cannot see at decode. So CpuChip cannot emit a per-step "k chips will
consume this" multiplicity.

**Resolution — push the kind-aware fan-out off CpuChip onto RistrettoEcallChip**
(which *can* read `op.kind`):

- **Tier 1 (kind-blind):** CpuChip emits **+1 per ristretto ECALL step** (pure
  opcode), RistrettoEcallChip consumes **−1 per call**. Clean 1:1 — the **point
  reads are universal** (present for both kinds, no skip-branch), so
  RistrettoEcallChip has a block for *every* call.
- **Tier 2 (fixed-base scalar_mult only):** RistrettoEcallChip, knowing kind,
  re-emits the *already-anchored* ts to the two comb chips, keyed on the
  authenticated scalar/output pointer. One-directional `CpuChip → Ecall → comb`.

This is the whole point: CpuChip's multiplicity stays pure-opcode; the
un-computable split lives only among chips that see kind.

## 4. Design

### 4.1 RistrettoEcallChip — uniform 96-row preprocessed period

Replace the flat byte-access layout with a fixed period (mirror the comb chips,
`ristretto_comb_compress_output.rs:79-88`).

**Preprocessed columns:** `CallIdx = floor(r/96)`, `ByteIdx = r % 96`,
`IsByteIdx0_pp = (r%96 == 0)`, `IsByteIdx95_pp = (r%96 == 95)`,
`IsWriteExpected_pp = (r%96 >= 64)` (output bytes are always ByteIdx 64-95 —
see the per-id layout below).

**Layout — every call occupies exactly one 96-row block, padded** (the current
trace emits 32 rows for fixed-base; v4 pads to 96 so call boundaries coincide
with `r%96 == 0`). Real mem-op rows are a contiguous **prefix** from ByteIdx 0;
the rest is padding (`is_real=0`). Point reads go **first** so the universal
anchor row is always ByteIdx 0:

| id | ByteIdx 0-31 | ByteIdx 32-63 | ByteIdx 64-95 |
|----|--------------|----------------|----------------|
| 110 fixed | point reads (Ptr=point_ptr) | padding | padding |
| 110 variable | point reads | scalar reads (scalar_ptr) | output writes (output_ptr) |
| 111 point_add | P reads (p_ptr) | Q reads (q_ptr) | output writes (output_ptr) |
| 112 reduce_wide | wide reads (wide_ptr+ByteIdx, 0..64 → spans 0-63) | (wide cont.) | output writes (output_ptr) |
| 113/114 binop | a reads (a_ptr) | b reads (b_ptr) | output writes (output_ptr) |

**Main columns** (extend the existing 5): keep `Addr[4]`, `Value[1]`, `Ts[8]`,
`IsWrite[1]`, `IsReal[1]`. Add `InitGate[1]`; three authenticated pointer
columns `Ptr0[4]`, `Ptr1[4]`, `Ptr2[4]` (operand ptrs in handler order;
`Ptr_{0,1,2}` = the registers φ[7,8,9] for 110, the corresponding operand regs
for the others); a held kind/id witness `Id[1]` and `IsFixedBase[1]`.

**Constraints** (all degree ≤ 2; gate `= is_real·(1 − IsByteIdx95_pp)` for the
held/cross-row ones):
1. Booleans: `is_real`, `IsFixedBase`.
2. **InitGate pinned:** `InitGate = is_real · IsByteIdx0_pp` (mirror
   `blake2b/mod.rs:198`). *Not* a free witness.
3. **Prefix-monotonicity:** `(1 − is_real) · is_real_next = 0` for
   ByteIdx ≠ 95 → real rows are a prefix, so ByteIdx 0 is real iff the block is
   non-empty → the InitGate cannot be dodged by leading padding.
4. **ts-equality:** `gate · (Ts_next[i] − Ts[i]) = 0`, i∈0..8.
5. **ptr-held-constant:** `gate · (Ptr_j_next − Ptr_j) = 0` for j∈{0,1,2}; same
   for `Id`, `IsFixedBase`.
6. **is_write pinned to the sub-block:** `is_real · (IsWrite − IsWriteExpected_pp) = 0`
   (reads at ByteIdx 0-63, writes at 64-95 — uniform across ids). Mirrors the
   comb chips' hardcoded is_write (`compress_output.rs:143`,
   `scalar_boundary.rs:190`). **[v4 refinement, ATTACK 5]**
7. **Per-byte Addr authentication, no field-wrap** (mirror
   `blake2b/mod.rs:1077-1106`): `is_real · (combine_le_u64(Addr) − active_ptr − offset) = 0`,
   where `active_ptr` and `offset` are selected from `(Id, ByteIdx)` (the
   per-id sub-block table above; 32-byte operands → offset = ByteIdx mod 32,
   reduce_wide's 64-byte operand → offset = ByteIdx). Plus a no-wrap range check
   on the carry so `ptr + offset` cannot field-wrap to an alias.
8. **Guaranteed ≥1 all-padding row** at the trace end so the cyclic last→row-0
   wrap is padding→padding and no cross-row gate fires across it (mirror
   `memory.rs:283-285`).

**Lookups produced/consumed:**
- `MemoryAccessLookupElements` producer (unchanged shape): `+is_real ×
  (Addr, Value, Ts, IsWrite, is_closing=0)`.
- `RistrettoCallLookupElements` **consumer**: `−InitGate × (Id, Ptr0, Ptr1, Ptr2, Ts)`.
- Tier-2 **producers** (fixed-base scalar_mult, gate `InitGate · IsFixedBase`):
  `+1 × RistrettoFixedScalarTs(scalar_ptr=Ptr0, Ts)` and
  `+1 × RistrettoFixedOutTs(output_ptr=Ptr2, Ts)`.

### 4.2 CpuChip — per-id ECALL gates + RELATION A producer + ptr authentication

Add five booleans `Is110Ecall … Is114Ecall` (`imm == id`, filled in
`trace_fill.rs` exactly like `IsBlakeEcall` at `:1251-1255`), and `Phi`
register-snapshot columns for each id's operand pointers (110 reads φ[7,8,9] =
scalar/point/output per `tracing.rs:486-491`; the others per their handlers —
**NB:** the register set differs per id; do not copy blake2b's `[10,7,8,9]`).

- **RELATION A producer:** at each `Is{id}Ecall`, emit **+1** into
  `RistrettoCallLookupElements` carrying `(Id=id, Ptr0, Ptr1, Ptr2, ts=Timestamp)`.
  Pure-opcode multiplicity. **The `Id` limb is load-bearing** — it disambiguates
  the five call kinds so a 111-block's consumer cannot satisfy a 110-step's
  producer (one relation with the `Id` limb is sound and simpler than five
  disjoint relations; the alternative is five relation types).
- **Pointer authentication:** at the same gate, emit register-read producers for
  the id's operand registers into the register-file relation (mirror
  `cpu/mod.rs:2080-2097`) so `Ptr0/Ptr1/Ptr2` are bound to the real register
  file at the step ts.

### 4.3 Comb chips — bind ts + addr to the anchored call

`RistrettoCombScalarBoundaryChip` and `RistrettoCombCompressOutputChip` already
have a preprocessed 32-row period (`CallIdx=floor(r/32)`, `ByteIdx`,
`compress_output.rs:79-88`). Add:
- **Tier-2 consumer** (−1/call, at the call's first row): from
  `RistrettoFixedScalarTs` / `RistrettoFixedOutTs` → forces the block's `Ts` ==
  the anchored call ts. The consumed `output_ptr` = the chip's `Addr` at
  ByteIdx 0 (since `Addr = output_ptr + 0` there).
- **Intra-call ts-equality** within the 32-row block (gated on the preprocessed
  period + is_real) — none of the three chips enforce this today.
- **Intra-call ptr-equality** — symmetric to ts-equality; hold the authenticated
  ptr constant across the block so the Tier-2 −1/call (which pins the ptr on one
  row) propagates to all 32. **[v4 refinement, ATTACK 3 — without it the other
  31 rows' `Addr = ptr + ByteIdx` are free to alias.]**
- **Constrained Addr** (replace the free witness): `Addr = authenticated_ptr +
  ByteIdx` with the same per-byte no-wrap carry as §4.1(7), and consume `Ts`
  from the anchor rather than a free fill.

### 4.4 Relations + format

New relations (`relations.rs`, `relation!` macro): `RistrettoCallLookupElements`
`(Id[1], scalar_ptr[4], point_ptr[4], output_ptr[4], ts[8])` = 21 limbs;
`RistrettoFixedScalarTs` `(scalar_ptr[4], ts[8])`; `RistrettoFixedOutTs`
`(output_ptr[4], ts[8])` (distinct types — a shared key would collide the two
comb consumers). No new *chips* (RistrettoEcallChip + comb chips are
restructured in place; CpuChip gains columns), so `chip_idx` / `BASE_COMPONENTS`
are unchanged. **Format `PROOF_FORMAT_VERSION` v7 → v8** (AIR/relation-set
change — old proofs must reject).

## 5. Honest balance

Let `C = F + V` scalar_mult calls (`F` fixed, `V` variable). **Tier 1:** CpuChip
`+C` into RistrettoCall (one per ECALL step), RistrettoEcallChip `−C` (one
InitGate per non-empty block) → 0; the `Id` limb makes this per-id. **Tier 2:**
RistrettoEcallChip `+F` into each of RistrettoFixedScalarTs / RistrettoFixedOutTs
(gate `InitGate·IsFixedBase`), comb chips `−F` each → 0. **Memory ledger
(unchanged):** point producers 32·C, scalar producers 32·V (Ecall) + 32·F
(boundary) = 32·C, output producers 32·V (Ecall) + 32·F (compress-out) = 32·C —
match MemoryChip's 32·C consumers each. Padding rows emit nothing. point_add /
reduce_wide / binop: each its own 96-row block + own RELATION-A 1:1 (k=1, no
comb fan-out).

## 6. Soundness summary (two adversarial rounds)

Round 1 broke v1 on two fundamentals — both fixed here:
- **Block structure:** v1's InitGate / ts-equality rode on free witnesses
  (flat chip, no period). Fixed by §4.1's preprocessed 96-period +
  preprocessed-pinned InitGate + prefix-monotonicity.
- **Ptr-auth circularity:** fixed-base RistrettoEcallChip never touches
  scalar/output ptr. Fixed by §4.2's register-authenticated ptrs flowing
  one-directionally through RELATION A → Tier-2 → comb.

Round 2 (5 attacks on v3) — the load-bearing **padding-exploit** and
**InitGate-placement** attacks now **defend**, as do **entry/exit forgery** and
**honest balance**; it surfaced the two v4 refinements above (comb ptr-equality
§4.3, is_write pin §4.1(6)). Key invariants the defenses rest on:
- **ts welded to a real step:** mem-op ts == block Ts (ts-equality) == InitGate
  Ts == CpuChip step Timestamp (RELATION-A 1:1) ∈ `[initial_ts, final_ts)`
  (`cpu/mod.rs:143-185`). Excludes 0 and `closing_ts`.
- **Reserved-ts forgery is *already* blocked** independent of this work by the
  MemoryChip group constraints (`memory.rs:258-292`: group-start ⇒ ts=0 write,
  group-end ⇒ is_closing=1) + the `is_closing=0` limb on every ristretto
  producer. The new work secures the *in-range* ts + the comb/Addr authentication.
- **Kind-routing is self-caught** (IsFixedBase is a free witness but not relied
  on for ts-anchoring): a variable call mis-marked fixed drops real scalar/output
  ledger producers (→ MemoryChip imbalance) or routes them to the comb chip whose
  EC-math rejects a non-fixed-base computation; a fixed call mis-marked variable
  must produce scalar/output rows whose `Addr` must equal the authenticated ptrs
  and whose EC-math must hold. Every real mem-op's ts is anchored by the 96-block
  (any kind) or Tier-2 (fixed comb) regardless of the kind witness.

## 7. Negative gate tests (§7-style, mirror `memory_merkle_gate.rs` / `ledger_readconsistency_gate.rs`)

- ristretto output-write `ts = 0` → REJECT (entry forgery);
- ristretto mem-op `ts = closing_ts` → REJECT (exit forgery);
- in-range but wrong `ts` on a single mem-op (break ts-equality) → REJECT;
- forged InitGate placement (real row at ByteIdx ≠ 0 with leading padding) →
  REJECT (prefix-monotonicity);
- extra all-real 96-block with no CpuChip producer → REJECT (RELATION-A imbalance);
- `Id`-mismatch (block claims id 111, producer is 110) → REJECT;
- forged comb `Addr` (≠ authenticated ptr + ByteIdx) → REJECT;
- comb mem-op `ts` ≠ anchored ts (break comb ts-equality / Tier-2) → REJECT;
- `is_write` flip on a sub-block → REJECT (is_write pin);
- variable-marked-fixed and fixed-marked-variable → REJECT (ledger / EC-math).

## 8. Implementation order

1. Relations: `RistrettoCallLookupElements` (+ `Id` limb), `RistrettoFixedScalarTs`,
   `RistrettoFixedOutTs` in `relations.rs`; wire into `AllLookupElements`.
2. CpuChip: five `Is{id}Ecall` columns + per-id `Phi` operand-ptr snapshots
   (`columns.rs` + `trace_fill.rs`), RELATION-A producer + register-read
   producers (`interaction.rs` + `mod.rs`), all gated per id.
3. RistrettoEcallChip: preprocessed 96-period; main cols `InitGate`,
   `Ptr0/1/2`, `Id`, `IsFixedBase`; constraints §4.1(1-8); RELATION-A consumer;
   Tier-2 producers; rewrite `collect_accesses` to lay out point-first, padded
   to 96, prefix-real.
4. Comb chips: Tier-2 consumers, intra-call ts + ptr equality, constrained Addr.
5. `PROOF_FORMAT_VERSION` v7 → v8 (+ history entry); verifier version gate.
6. Tests: §7 negative gates (new `tests/ristretto_ts_gate.rs`); re-run the
   ristretto chip-isolated harnesses + `comb_value_sweep`; `voucher_check_smoke`
   (~207s) + a `DBG_MAX_SEGS=2 SEG_STEPS=100000` capstone revalidation.

## 9. Open implementation risks

- The per-id `Addr` offset arithmetic (32-byte operands vs reduce_wide's 64-byte
  wide) — get the `(Id, ByteIdx) → (active_ptr, offset)` table exactly right;
  it's the bookkeeping the soundness rests on.
- Padding inflates RistrettoEcallChip's trace (fixed-base 32 → 96 real-or-padded
  rows); cost is bounded and small vs the page machinery (capstone ~17 GB at
  100k steps), but confirm log-size doesn't regress the capstone.
- Per-id operand register sets for ids 111-114 must be read from their handlers
  (`handle_*_ecall` in `tracing.rs`), not assumed.
- `RistrettoCombScalarBoundaryChip`'s `CallIdx` is a *witness* (not preprocessed
  like CompressOutput's) — confirm its intra-call equality gates are sound or
  promote it to preprocessed.
