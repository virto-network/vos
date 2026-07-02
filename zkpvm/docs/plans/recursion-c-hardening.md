# P5.3 step 4 — increment (c) hardening + (d): making the DEEP anchor load-bearing

Status: **increment (c) MECHANISM landed + proven** (commit `2c96004`, voucher-state-
transition, LOCAL): the full multi-batch factored eval `eval[qi] = Σ_b denom_inv[b][qi]·
(L[b][qi] − p.y·A[b] − B[b])` over all 11 batches, carried to the FRI layer-0 `running`
via the latched `eval_lat[qi]`. `child_full_air_satisfied` + `child_full_measure` GREEN
@ log 17 (degree ≤ 2, ~60 min/2-proves; FRI-fold tamper rejected). Issue B (producer
α-chain off `squeeze[2]`, `deep_z[0]`↔OODS) landed.

**The adversarial review (Workflow, 17 agents, 5 dims × per-finding verify) found the
anchor is proven as a MECHANISM but NOT yet LOAD-BEARING.** This doc plans the work to
make it sound, then the (d) bindings. Read `project_recursion_build` (the "INCREMENT (c)
LANDED" block) + `recursion-p5.md` (P5.3) first. Anchors are `tests/recursion_child_full.rs`
unless noted (line numbers ≈ commit `2c96004`; re-grep before editing).

---

## The two confirmed-real findings (the make-or-break for (c) soundness)

**F1 (HIGH) — `fri_fold_bit` is a free boolean.** `let fold_bit = eval.next_trace_mask()`
(~2001) is a WITNESS, constrained only by booleanity (`fold_bit·(fold_bit−1)`, ~2020) and
the mux def (`mux_fold == fold_bit·(e1−e0)`, ~2021). Layer-0 `running = e0 + mux_fold`
(~2022) is consumed ONLY by the eval_lat bind (~2288); the cross-layer carry check uses
`is_run = is_fri_layer[1..]` (EXCLUDES layer 0, ~2016/2039) and `fri_folded = e0+e1+prod`
is fold_bit-INDEPENDENT. ⇒ a prover flips fold_bit so `running` = the coset SIBLING (also
merkle-authenticated) instead of `first_layer_evals[qi]`.

**F2 (HIGH, the deeper one) — `deep_px`/`deep_py` are free witnesses.** `deep_px =
eval.next_trace_mask(); deep_py = ...` (~2108-2109) are used only in the in-AIR CM31 denom
(~2231-2234) and `p.y·A` (~2228). NOTHING ties them to the genuine query domain point
`lifting.at(bit_reverse(q0))`. With free `p` the prover SOLVES `eval[qi]` to ANY value ⇒
**the DEEP coupling (trace leaves ↔ OODS) is VACUATED** (eval == running holds trivially).

**Compounded:** free `p` makes `eval[qi]` solvable to any value; free `fold_bit` makes
`running` either coset leaf. Either alone defeats (c)'s stated goal. **Pinning `p` to the
genuine query point ALSO closes F1** (then `eval` is forced to the q0 quotient, so the
bind forces `running` = the q0 leaf, forcing `fold_bit = q0&1`).

**ROOT CAUSE — a pre-existing FRI gap the DEEP anchor exposed:** child_full's FRI uses the
HOST twiddle (`fri_twid = read4()`, ~2003, "forced by the chain + decommit + last-layer"),
so the FRI **query positions `q0` are never bound in-AIR to the FS draw**. The merkle
decommit authenticates the leaf at the *decommitted* path, NOT that the path index is the
FS-drawn `q0` (a prover may decommit at chosen positions). `sample_query_positions` draws
`q0` from the channel AFTER the 14 fold-alpha squeezes (`verify.rs:992`,
`FriVerifier::sample_query_positions`). Binding `q0` to that draw is the fix — it completes
FRI query-soundness AND makes the DEEP anchor load-bearing.

**F3 (rated critical, but PREPROC-MITIGATED, low priority):** `deep_eis[e][b]` routing
one-hots (read via `get_preprocessed_column`) are not pinned in-AIR to `deep_ebatch`. But
`eis`/`route`/`mslot`/`qsel` are ALL trusted preprocessed selectors — segment-invariant,
pinned by the program-commitment / W0 allowlist in deployment (the consumer-lanes reviewer
correctly REFUTED it). Cheap self-certification is defense-in-depth (see Priority 3).

---

## Priority 1 — INTEGRATION FULLY PROVEN 2026-06-23 (commits `1143ae2`+`d14ad23`+`4fc8788`+`edddee4`)

F1+F2 are CLOSED in `child_full`, validated 3 ways: `child_full_air_satisfied` GREEN
(value); `child_full_measure` GREEN @ log 17 (degree ≤ 2, 3847s, perturbed FRI fold
rejected); `child_full_q0_tampers` GREEN (the F1/F2 pins BITE — a flipped fold bit +
a perturbed eval point each make the AIR unsatisfiable ⇒ load-bearing). NOTE: the
Layer-2 producer's 248 bit-cols push the prove to ~60 GiB — cut the width (1
word/row + latched `out`) before the 76-seg federation re-prove. Built as 3 provable
checkpoints:
- **Checkpoint 1 (`1143ae2`) — pos_lane climb accumulator.** Reconstructs
  `query_positions[qi]` in-AIR from the trace-tree `mk_bit` (tree-0 `m_node` rows
  carry `pos_level`; lane sums `mk_bit·2^level` keyed by `nqsel`, `pos_inc` witnessed
  deg2). The F-A2 single source of truth.
- **Layer 1 (`d14ad23`) — F1/F2 geometric closure.** Per row (for `qi_p` = evalfin
  slot OR FRI-layer-0 fold query) `posbit` decomposes the position + the conditional
  point-add chain over the lifting half-coset derives `p=lifting.at(brev(pos))`
  parity-correct; `deep_px/deep_py` PINNED to it (F2); `pos_row` tied to `pos_lane`
  on evalfin+FRI-layer-0; `fri_fold_bit` pinned to `posbit[0]` (F1). `lifting_log_size
  ==POS_LOG` asserted (F-Q0-5).
- **Layer 2 (`4fc8788`) — draw↔slot FS permutation.** Producer authenticates each
  FS-drawn position (`out[e]` low-16 + 31-bit canonicity guard, F-Q0-2); consumer
  drains `pos_lane[qi]`; 8 QPos entries APPENDED to the DEEP logup (independent
  `QPosRelation` ⇒ combined `claimed_sum==0` forces both ⇒ `{pos_lane}=={FS draws}`).
  The existing `deep_claimed!=0` guard covers the combined sum (F-A4).

DONE: degree confirmed + the `fold_bit`/`deep_px` negative tests GREEN
(`child_full_q0_tampers`, via a `gen_trace` `q0_tamper` hook + the fast assert path).
Priority 1 is fully landed. NEXT: Priority 2 = (d) bindings; Priority 3 = the
`is_query_draw·(1−is_squeeze)` self-cert + F3.

## Priority 1 — DE-RISKS LANDED (2026-06-23, commits `abf6aca`+`df83d90`)

All THREE new mechanisms the q0 binding needs are PROVEN standalone (Route A
chosen; Route B is not a shortcut). The integration is now ASSEMBLY of proven
parts.

- **Route-A spike GREEN** (`recursion_child_verify::route_a_query_draw_grounding`,
  no lib change): on a REAL segment, `sample_query_positions` = `ceil(38/8)=5`
  squeezes × 8 limbs (`draw_u32s` = `squeeze8().map(|m| m.0)`, NOT 7 — our channel
  returns 8); `q = limb & ((1<<lifting_log_size)-1)` = the limb's low 16 bits;
  low-16 recompose reproduces each `q`; `sorted+dedup(raw draw order) ==
  query_positions` (38 DISTINCT). **The draw order is genuinely UNSORTED**
  (`[14670,45304,25894,…]` vs sorted `[170,1415,…]`) ⇒ a draw↔slot permutation IS
  required. The query-draw squeezes = every `Squeeze` AFTER the last `Pow` record.
- **Point/parity/pin de-risk GREEN** (`recursion_q0_point.rs`, log 6, ~7s):
  `fri_twiddle_chip` ported to the CIRCLE domain. `lifting =
  CanonicCoset::new(L).circle_domain()`. With `j = brev_L(q)`, `j`'s top bit is
  `q&1` ⇒ `j < |half_coset|` iff `q` even. Even-rep `p_even =
  lifting.at(brev(q&~1))` = a conditional-point-add chain over `lifting.half_coset`
  driven by bits `1..L` (`Q_idx = (half.step_size·2^{L-2-idx}).to_point()`);
  `p.x = p_even.x` (parity-independent), `p.y = (1 − 2·q0)·p_even.y` (ODD queries
  flip y — the review's parity finding). Pins free `fold_bit==q0`, free
  `deep_px/deep_py==(p.x,p.y)`, + membership `px²+py²=1`. Matches stwo `lifting.at`
  for all 64 indices; tampered qbit / fold_bit / deep_px each rejected; deg ≤ 2.
- **Draw↔slot permutation de-risk GREEN** (`recursion_q0_perm.rs`, log 7, ~3s):
  single-component self-balancing logup (the `recursion_deep_couple` shape, tuple
  = `[pos]`). PRODUCER emits each FS-authenticated draw position (bound to a
  squeeze limb's low 16 bits, +1); CONSUMER drains each slot position (−1);
  `claimed_sum==0` forces `{slot}=={drawn}` (both distinct ⇒ set equality). A slot
  position not in the draw set (imbalance) AND a producer bit divorced from its
  limb (`recompose≠w`) each rejected; deg ≤ 2.

### Integration recipe into `recursion_child_full.rs` (the remaining ~60-min build)

1. **Route-A producer rows (FS authentication).** The 5 query-draw squeeze rows
   are the `Squeeze` records after the last `Pow` (extract them in `build_inputs`;
   optionally expose the boundary from `extract_recursion_data`). For each of the
   38 used draws `d` (word `d%8` of squeeze `d/8`): a preproc `is_query_draw`
   indicator on that squeeze row + 31 boolean `qlimb_bit[d]` cols, bound to the
   squeeze output limb via `is_query_draw·(recompose31 − out[d%8])` and gated `(1 −
   is_squeeze)`; `q_d = Σ_{k<16} qlimb_bit[d][k]·2^k`. Emit the position-permutation
   logup `+1` with tuple `[q_d]` (8 entries/query-draw row; the 5th row's words 6,7
   carry 0 mult). NOTE the 8-per-row producer is the only new structural wrinkle vs
   the de-risk (which used 1 producer/row) — model it on the DEEP consumer's
   8-entries/row `finalize_logup_in_pairs`.
2. **Per-slot position from the merkle climb + consumer rows.** Reconstruct each
   slot's position `pos_slot[qi]` from the trace-decommit climb (`mk_bit` over the
   16 levels = `query_positions[qi]`'s bits, since path index = query index, the
   identity remap `build_inputs` already asserts) into a latched per-slot value, OR
   add per-slot `posbit[qi]` cols tied to `mk_bit` at the climb rows. Emit the
   permutation logup `−1` with tuple `[pos_slot[qi]]` (one per slot). The balance
   binds `{pos_slot}=={q_d}` ⇒ the decommitted positions are FS-drawn (closes FRI
   query-soundness) and `pos_slot` feeds p/fold_bit (so leaf & point share the
   position). This needs a SECOND relation (`QueryPosRelation`) + its interaction
   columns alongside the existing `DeepLeafRelation` (a 2nd `claimed_sum`,
   2nd `mix_felts`); or fold both into one relation with disjoint tuple shapes.
3. **Derive p[qi]/fold_bit[qi] + pin (closes F1/F2).** Per slot, run the
   `recursion_q0_point` gadget on `posbit[qi]` → `(px[qi],py[qi])`, latch
   `(px_lat[qi],py_lat[qi])` (held by `not_last`, like `deep_eval_lat`). On the
   evalfin row `qi`: `deep_efsel[qi]·(deep_px − px_lat[qi])==0` (+ py). On the FRI
   layer-0 fold row `qi` (`deep_flsel[qi]`): `deep_flsel[qi]·(fri_fold_bit −
   posbit[qi][0])==0`. Add membership `deep_px²+deep_py²−1==0` (ungated, holds on
   the filled p_qi every row — deep_air pattern).
4. **Negative tests + gate.** Add `fold_bit_tamper` (flip the layer-0 `fold_bit`)
   and `deep_p_tamper` (perturb `deep_px` on an evalfin row) to the tamper enum;
   both must reject at PROVE-or-verify. Run `child_full_air_satisfied` (assert,
   ~74s — catches VALUE bugs) FIRST, then `child_full_measure` (degree, ~60 min).
   Every new pin must stay deg ≤ 2 (witness any deg-2×preproc).

### Recipe REFINEMENTS from the adversarial review (2026-06-23, Workflow `wzygmsixx`, 23 agents)

The review independently re-verified the three de-risks' MATH as correct (circle-point/parity
exhaustively cross-checked vs stwo `lifting.at` incl. the real L=16; the single-tuple logup IS a
sound multiset-equality; the Route-A limb arithmetic — 8 limbs/squeeze, `q=word&mask`, 38-of-40,
sorted+dedup==query_positions — is EXACT). NO bug in the landed code. 9 confirmed findings, ALL
forward-looking integration obligations — fold these into the steps above:

- **[HIGH, F-A2/F-Q0-1/QP-4] ONE per-slot position, single source of truth.** The DEEP/FRI chain
  is keyed by a PREPROC slot one-hot (`deep_qsel/efsel/flsel`), while the position VALUE is the
  prover's `mk_bit` climb — so the slot↔position tie (the actual F2 load-bearer) is implicit. Make
  `pos_slot[qi]` ONE latched per-slot register reconstructed from slot qi's trace-tree climb
  `mk_bit` (`tree_paths` sets `bits[level]=(query_positions[qi]>>level)&1`, child_full ~717), and
  drive ALL of: the perm CONSUMER tuple `[pos_slot[qi]]`, the `q0_point` p/fold_bit chain, AND the
  FRI-layer-0 climb from that SAME register (add `qbit[qi][k]==mk_bit@level` ties). NEGATIVE TEST:
  pair slot qi's leaf with a `p` derived from a DIFFERENT drawn position (both in the draw set) and
  assert reject — the standalone tampers do NOT cover this splice.
- **[MEDIUM, F-A4] QueryPosRelation needs the `claimed_sum != 0` guard.** stwo only enforces
  `Σ(fractions)==claimed_sum` (self-consistent for ANY value) ⇒ a free claimed_sum makes the perm
  logup VACUOUS (the exact bug class as the DEEP `deep_claimed!=0` guard, child_full ~3868). Add the
  verify-side `if query_pos_claimed != 0 { Err }` (mirrors `deep_claimed`) OR the in-AIR
  `is_last·last_cumsum==0` self-cert (Priority-2 d.3) for BOTH interaction columns. NEGATIVE TEST:
  perturb the QueryPos claimed_sum → reject.
- **[LOW, F-Q0-2] M31 canonicity guard on the 31-bit recompose.** `Σ_{k<31} bit·2^k == out[d%8]`
  is NON-injective: `out==0` (≡ P=2^31-1) admits the all-ones decomposition ⇒ low-16 = 0xFFFF ≠ 0.
  Prover-uncontrollable (~2^-31/limb, FS-fixed) + the existing s2 PoW recompose (child_full ~1635)
  shares the pattern, so it's negligible+pre-existing — but a CHEAP deg-2 fix exists: witness `u`
  with `(Σ_{k<31}(1−bit_k))·u == 1` (forbids exactly the all-ones alias ⇒ injective). Add it.
- **[INFO, F-Q0-5] Parameterize from `data.lifting_log_size`.** The gadget's `Q_idx` exponent +
  N_CHAIN are hard-wired to L; the port MUST drive them with `data.lifting_log_size` (=16, the
  domain `sample_query_positions` draws from AND the DEEP `lifting.at` domain — proven identical).
  Add the cheap host assert: in-AIR `(px,py)` for slot 0 == `lifting.at(brev(query_positions[0]))`.
- **[HIGH-rated, QP-1, but PRE-EXISTING completeness, not soundness] draw collisions.** ~1.07% of
  segments have a birthday collision among the 38 raw draws ⇒ `Queries::new` dedups ⇒
  `|query_positions| < 38`. child_full ALREADY hard-asserts `len()==38` (~3699, "held empirically"
  per increment b) ⇒ colliding segments are ALREADY unsupported; the perm adds no NEW soundness gap
  for the supported 38-distinct case (the de-risk target). Proper multiplicity-aware handling is
  future work tied to general collision support across child_full — NOT (c)-hardening scope. Note it.

## Priority 1 — bind the FRI query positions q0 (closes F1 + F2; completes FRI soundness)

**GOAL.** Make `q0` available in-AIR as a transcript-AUTHENTICATED value, then derive
`fold_bit = q0&1` and `p = lifting.at(bit_reverse(q0))` from it and pin them.

**THE DESIGN QUESTION — where does authenticated q0 come from? Two routes, pick after a spike.**

### Route A — replay `sample_query_positions` in the ChannelChip (the principled fix)
stwo draws each query position by pulling `log_domain_size` random bits from the channel
(`Queries::generate` → `channel.draw_random_bytes` → bytes→positions). The ChannelChip
already replays the transcript squeezes and binds the fold alphas to specific squeezes
(`is_fold_draw[i]`). The query-sampling draws are the squeezes AFTER the 14 fold alphas.
- **Sub-task A1 (spike):** read stwo `fri.rs` `sample_query_positions` / `Queries::generate`
  + `channel.rs` `draw_random_bytes` at rev e128672. Determine EXACTLY how many channel
  draws (squeezes/perms) the query sampling consumes and the bits→position arithmetic
  (endianness, masking to `log_domain_size`, dedup/sort). `extract_recursion_data`
  (`verify.rs:992`) already calls it on the recording channel — instrument it to dump the
  per-query draw→position mapping for one real segment.
- **Sub-task A2:** add a preproc `is_query_draw[j]` (the query-sampling squeezes, the analog
  of `is_fold_draw`) + per-query witnessed position bits `qbit[qi][k]` (k in 0..log_domain),
  each boolean, bound to the squeeze output bits via `is_query_draw·(reconstruct − out)`.
  Reconstruct `q0[qi] = Σ_k qbit[qi][k]·2^k`. (Watch: the positions are SORTED+DEDUPED in
  `query_positions`; the channel draws them in DRAW order then sorts — bind the DRAW-order
  values, then the AIR's per-query rows use the sorted order. Map carefully, or bind the
  sorted set via a permutation/membership argument.)
- **Cost:** the channel block grows by ~`N_QUERIES·log_domain` boolean cols + the draw
  binding. Moderate. De-risk the draw replay standalone (extend a channel_chip-style test).

### Route B — exploit the trace merkle climb (lighter, but check soundness)
The trace trees have height = `lifting_log_size`, so the per-query merkle climb's path bits
(`mk_bit` on the decommit rows) ARE `q0`'s bits — BUT the merkle authenticates the leaf at
the *decommitted* path, not that the path == FS `q0`. **So Route B alone does NOT bind q0
to the FS draw** (a prover decommits at a chosen position). Route B is only valid if
COMBINED with a binding that the decommitted trace positions equal the FS query positions —
which is exactly Route A. ⇒ Route B is NOT a shortcut; it reconstructs q0 from `mk_bit` for
the p/fold_bit derivation, but the FS-binding must still come from Route A. **Recommendation:
do Route A for the FS-binding; reuse the climb bits only if it simplifies the q0 plumbing.**

### Deriving + pinning fold_bit and p (once q0 is authenticated)
- **fold_bit:** `deep_flsel[qi]·(fri_fold_bit − qbit[qi][0]) == 0` on the layer-0 fold row
  (qbit[qi][0] = q0&1). Degree 2 (preproc·deg1). Add a fold_bit-flip negative test.
- **p = lifting.at(bit_reverse(q0)):** port the de-risked **`fri_twiddle_chip`**
  (commit `11baf35`, `tests/fri_twiddle_chip.rs`) — it DERIVES a circle/line domain point
  from the query-index bits via a depth-L conditional-point-add chain (`domain_pt(q) =
  initial + Σ_{q_k=1}(step·2^{L-1-k}).to_point()`, each per-bit add deg-2). Drive it with
  `qbit[qi]` (bit-reversed) over the `lifting` circle domain to get `(px,py)`. Then pin
  `deep_px`/`deep_py` per evalfin row to the derived point via a latched per-query carrier
  `(px_lat[qi], py_lat[qi])` (held by `not_last` like `deep_eval_lat`): derive on the q0
  row, bind on the evalfin row `deep_efsel[qi]·(deep_px − px_lat[qi]) == 0` (and py). Also
  add the circle-membership `deep_px²+deep_py² − 1 == 0` (cheap deg-2 sanity).
  - **PARITY note (from the review + the original FRI-review correction):** `p.y` is
    per-query parity-dependent (odd queries `p.y = −even.y`); the derived `lifting.at(brev(q0))`
    already encodes the full q0 incl. parity, so it is parity-correct by construction — do
    NOT use the bare fold twiddle (which drops the parity).

### De-risk + negative tests (mandatory before the log-17 prove)
- Standalone (small log): the q0-bit binding + the fri_twiddle_chip point derivation +
  the fold_bit/p pins, with q0 bound to a synthetic "squeeze". Prove + tamper (flip a
  qbit, flip fold_bit, perturb p) each rejected.
- In child_full: add `fold_bit_tamper` (flip the layer-0 fold_bit) and `deep_p_tamper`
  (perturb deep_px on an evalfin row) to the tamper enum + assert both REJECT at prove or
  verify (recall: a leaf/structure tamper bound by `is_last·(.)` is caught at PROVE not
  verify — treat prove-OR-verify failure as rejection).
- GATE: `child_full_air_satisfied` (assert) THEN `child_full_measure` (degree, ~60 min);
  assert does NOT catch degree — every pin must keep deg ≤ 2 (witness any deg-2×preproc).

**COST: 1 spike (Route-A draw replay) + 1 standalone de-risk + 1 integration + ~60-min
prove(s). The biggest remaining (c) item; budget a full session.**

---

## Priority 2 — increment (d): the deferred input-side bindings

These close the OODS-INPUT side (the review confirmed the producer α-chain + z[0]↔OODS are
already sound; these are the remaining known gaps).

**(d.1) batch-≥1 sample points z_b ↔ transcript.** Currently `deep_z[b]` (b≥1) are
host-latched (only z[0] is bound to OODS). The shifted batches' points are the OODS point
shifted by the fixed mask offsets (z_b = oods · g^δ_b, a group op with a segment-invariant
δ_b). Derive each `deep_z[b]` in-AIR from the bound `deep_z[0]` (= OODS) + the fixed offset
(a conditional-point-add by a preproc constant point, like the fri_twiddle gadget). This
binds all 11 batch points to the transcript. (Confirm the exact offset→point map from
stwo's `ColumnSampleBatch::new_vec` / the mask-point construction.)

**(d.2) v ↔ `mix_felts(sampled_values)`.** The OODS sample values `v` (which the embed
routes as its mask leaves, and which A/B absorb) are absorbed into the transcript via
`mix_felts(sampled_values.flatten_cols())` (the ~8500-perm absorb that dominates the
transcript). Bind the embed's routed `v` to that absorb so A/B (host) are pinned to the
TRANSCRIPT v, not just over-determined. This is the "full non-vacuousness" the memo flags.
Couples the DEEP producer's implicit-v (via A/B) to the embed mask AND the transcript.
Heavier (the absorb is huge); may need its own session.

**(d.3) in-AIR self-certifying claimed_sum boundary.** Replace/augment the verify-side
`deep_claimed != 0` check with an in-AIR `is_last_row · last_cumsum == 0` on the DEEP logup
interaction column (self-certifying; the verify-side check is currently sound but relies on
the verifier remembering to check). Needs accessing the interaction cumsum at the wrap
(read the last logup interaction column at `is_last`). Small; fold into the next re-prove.

---

## Priority 3 — F3 defense-in-depth (optional, low)

Pin `deep_eis[e][b]` to the one-hot of `deep_ebatch[e]` in-AIR (all deg ≤ 2, near the
consumer constraints ~2200): booleanity `eis·(eis−1)`; partition-of-unity `Σ_b eis[e][b]
== valid_e` (valid_e from `deep_mslot[e] != 0` or a preproc validity col); label tie
`Σ_b b·eis[e][b] == deep_ebatch[e]`. Makes the routing self-certifying without the
allowlist. NOTE this applies equally to `route`/`mslot`/`qsel` (all trusted preproc) — do
it as a consistent pass or not at all; not (c)-specific.

---

## Workflow notes (lessons from the (c) build)

- **Cheapest value-bug catcher:** a host-side `assert_eq!(deep_eval_vec[evalfin] ==
  first_layer)` invariant (NOT `debug_assert!` — `--release` strips it). It caught the
  batch-0 duplicate bug (the 8 composition columns appear in batch 0 TWICE with different
  α^i — model every col as carrying ALL its (batch,c) entries, ≤3 = `N_ENTRY_PER_SLOT`).
- **Iterate on `child_full_air_satisfied`** (~74 s incl. build) for value/cursor bugs;
  `child_full_measure` (~60 min) is the DEGREE gate only — assert never catches degree.
- Keep every `add_constraint` deg ≤ 2: witness any deg-2 product, and a deg-2×preproc =
  deg-3 is forbidden (caught ONLY at prove). EF·F is defined, F·EF is NOT (flip operands).
- Latched cols (z, A, B, alpha, eval_lat, and any new px/py carriers) must fill ALL n rows
  incl. padding, else the `not_last` constancy breaks at the plan/padding boundary.
- Run heavy proves backgrounded + a harness-tracked waiter (nohup is NOT tracked); free
  RAM first (`pkill -f rust-analyzer`); the box is 62 GiB, (c) peaks ~24 GiB at log 17
  (~30 GiB headroom, NO swap — watch new wide additions).
- `#![cfg(feature = "poseidon2-channel")]`; run `--features poseidon2-channel`; `mix_felts`
  needs `use stwo::core::channel::Channel`. Commits LOCAL, `--no-verify`, NEVER
  Co-Authored-By, no backticks in nu commit messages; `rustfmt --edition 2024 <file>`.

**START HERE next session:** Priority 1, Route-A spike — instrument
`extract_recursion_data` (`verify.rs:992`) to dump the `sample_query_positions` draw→bits
mapping for one real segment, and read stwo `fri.rs`/`channel.rs` to nail the draw count +
bit arithmetic. That determines the `is_query_draw` indicators + the q0-bit binding shape.
