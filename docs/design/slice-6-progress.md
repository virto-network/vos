# Slice 6: progress

The log of build step 6, against `slice-6-on-chain.md`. Every number is
tagged [measured], [model] or [est]; the research behind the plan is
`research/slice-6/`.

## Step 6.0: the remaining feasibility spikes, and the docs

Throwaway code on local branches, each spike with its gate and fallback
(`slice-6-on-chain.md`, 6.0). The spikes' logs land here as they finish.

### 6.0a: the in-kernel prologue, measured before the keyspace changes

Running. It sets `Limits::served` and the served witness's transport.

### 6.0b: the JAM venue's program and PolkaJam

Running. It decides the proof's transport on JAM (the work item's payload
or a preimage).

### 6.0d: the docs

**The research** was copied into `research/slice-6/` with the plan
(`27967322`). Every reference the plan makes to it resolves. Four
pointers did not, and now do:
- `spaces-pallet.md` cited `../spaces-pallet-research.md`,
  `owner-decisions.md` and `vos-core/docs/design/identity-and-authority.md`;
  they are now paths from the repository's root;
- `spaces-pallet-research.md` and `owner-decisions.md` pointed at the
  staged `stage/spaces-pallet-design.md`, now `docs/design/spaces-pallet.md`;
- `plan3-review.md` names the staged files it reviewed; a line maps them
  to their homes.

**`doc-fixes.md`'s [now] and [decision N] items, applied:**

| doc | applied | left for their step |
|---|---|---|
| `proving.md` | 26: 2–7, 12–20, 22–30, 34, 35 | 1 (6.22), 8 (6.13), 9 (6.15), 10 (6.5), 11 (6.10, 6.19), 21 (6.0a), 31 (6.1, 6.9), 32 (6.13), 33 (6.5) |
| `recursion-air.md` | 8: 1–5, 8–10 | 6, 7 (6.4) |
| `core-model.md` | 11: 4, 6, 9, 10, 12–18 | 1, 5, 7 (6.13); 2, 3 (6.12); 8 (6.18); 11 (6.6) |
| `identity-and-authority.md` | 8: 1–8 | none |
| `research/slice-5/kreivo-pallet.md` | 15, as a note at the top; its body stays the record | none |
| `clerk-across-spaces.md` | 13: 1–3, 5–14 | 4 (6.13) |

81 items in all. Every replaced number was checked against its source:
the masked wrap's against `spike6a-mask-wrap.md`, format 39's counts
against `spike6b-masked-bits.md`, Kreivo's against `spike6c-kreivo.md`,
the estimates against the plan's, and against the code
`Limits::attest` (64 KiB on VOS, 2 KiB on JAM, `agent/wire/src/abi/cap.rs`),
the built `Statement` and its id (`pvm/proof/statement`), the Stwo pin
(olanod/stwo `ab294189`) and the statement fixtures' bytes (375 KB, the
segment fixtures beside them).

**Applied with a change, and why:**
- **Mixed tags** (a decision and a step): `proving.md` 19 (decisions
  10–12; 6.16) and 24 (decisions 1, 6, 7; 6.14), and
  `identity-and-authority.md` 1 (decisions 1, 2, 7; 6.14). Applied now as
  design: the decisions are taken and `spaces-pallet.md` exists. Their
  steps confirm them as built.
- **Not yet true of the code,** so worded as placed rather than done:
  - `core-model.md` 12 (decision 3): the refine-bundle path (format 36)
    is "retired by the owner's decision of 2026-10-19, and deleted at
    slice 6's 6.9", not "deleted"; it is still in the code;
  - `core-model.md` 14 and 17: requirement 4 is "met by the statement
    (slice 5); format 39 at 6.6", and the track's item 9 stays unstruck,
    placed in slice 6, since format 39 is not built yet.
- **`clerk-across-spaces.md` 10** rests on the Clerk's decision 4 (the
  aggregate rows), still open in that draft: written as "under decision
  4's aggregate rows, a pair reads two rows".
- **`clerk-across-spaces.md` 1:** the header says the steps "are re-read
  against them where marked" in place of the item's "(items 2–14)", which
  names `doc-fixes.md`'s items, not anything in the Clerk's doc.
- **`proving.md` 26:** the total is recomputed with slice 6 in full
  (32–49 engineer-weeks, its spikes, acceptance and the slice-5 rest
  included): about 76–118, from 58–89.
- **`proving.md` 28:** the two deferred items became decisions 10 (the
  window length) and 11 (the pallet's home); 11 says it replaces
  decision 7's "in slice 6", which the item did not name.
- **`proving.md` 20:** the JAM proof's transport is written as the item
  has it, the payload unless 6.0b finds it cannot carry the proof; 6.0b
  settles it.

**Not applied:** none of the [now] or [decision N] items was wrong
against the code or the owner's decisions.

**Left as they are,** outside the items: `clerk-across-spaces.md`'s goals
and C.8's acceptance still name the JAM aggregate agent and a PolkaJam
run; they are re-read when the Clerk is scheduled.

**The rename** (decision 15): the Clerk's slice-6 draft is
`clerk-across-spaces.md` by `git mv`, its steps renumbered C.0–C.8, and
every reference in `docs/` follows. The research records that cite the
draft by line keep their numbers, each with a note that they are the
draft's before the rename.

**Commits:** `bf742664` `proving.md`; `c0978c64` `recursion-air.md`;
`0719aaa0` `core-model.md`; `21fb8e4a` `identity-and-authority.md`;
`04e8a3cb` `kreivo-pallet.md`'s note; `d29b36f0` the rename and its
references; `c75c11d5` the Clerk's items; `4a49afa8` the research's
pointers; and this entry.

**Review** (Opus): mostly clean; 2 medium and 4 low findings, folded in
one commit:
- **medium:** `core-model.md` §9.3's agent root stated as built: now
  "[decided; built at slice 6's 6.11 (agent root) and 6.14 (space
  root)]", "VOS will keep"; `proving.md` §3.5's fixed-layout decode sat
  in the "Built (slice 5's 5.14) [measured]" list: now its own "Levers"
  bullet, "format 39 is to decode a fixed layout (6.4)";
- **low:** requirement 4 "met by the statement (slice 5); format 39 at
  6.6", item 9 unstruck; "masked from slice 6" (`identity-and-authority.md`
  §11) and "to be verified in a JAM statements service's refine (slice
  6)" (`core-model.md` §11.1); `Limits::served` "(proposed; set by
  6.0a)" in `proving.md` and the Clerk doc; the JAM transport "(or as a
  preimage; 6.0b decides)"; the Clerk doc's "Decided in this draft"
  marked superseded by C.0, C.4 and C.5 where they are, and its decision
  4's aggregate read at one cut against the carried commitment;
  `proving.md` A.6's long line rewrapped.

**Gates:** docs only, so no `just check`; no reference to the
draft's old name is left in `docs/`.

### 6.0e: a Rust client on a Kreivo dev chain

Running. It picks the subxt release that reads stable2606-2's metadata,
or the raw JSON-RPC fallback, for 6.17b.

## Step 6.1: format 39 and the masked security count

**The tool** (`pvm/proof/src/security.rs`), ported from spike 6b
(`1b76b028`):
- `SecurityShape::composition_point_doublings` (`j`): the DEEP term is
  multiplied by `2^j`; 0 in every unmasked shape (the registry's and
  `framework_access`' `security_shape`), and a `j` above the degree bound
  is refused;
- `SecurityShape::variant_c()`: from the tallest component's `m`, the
  degree bound `m+2`, the trace length `m+1`, the composition bound `m+2`,
  `j = 1`. It moves only the levels; what the masking commits beside the
  AIR's columns is the caller's to add;
- the search for the best multiplicity is one `Analysis::best`, the other
  terms a named `OtherTerms`; a test-only `term_bits` reports every term
  at the `m` the count is taken at.

**The entry** (`pvm/proof/src/format.rs`):
- `ProofBytes::{Postcard, FixedLayout}`, a new `Format` field (pin A):
  every existing format `Postcard`, 39 `FixedLayout`;
- `MASKED_WRAP`, number 39, pin A's parameters (blowup 32, 24 queries,
  PoW 26, interaction PoW 8, fold step 3, last layer 2^6, affine
  batching, Blake2b-256, `Lossless`), masked, floors 100 / 80,
  `Reserved`;
- `MASKED_WRAP_REFERENCE`: `WRAP_REFERENCE.variant_c()` plus R2's
  blinding (12 main and 8 interaction columns, 2 constraints, fractions
  6, 5 and 7 a row) and the composition's columns as pin A commits them
  (4 whole and R's 8, where the split composition had 8). Every sampled
  column at two samples, as `WRAP_REFERENCE` counts its own: 2 × (458 +
  24) = 964 sampled values, against the spike's 956 with a 4-column R;
- `RETIRED` gains 40, its reason in the doc: never registered, but spike
  6a's measured masked wrap at blowup 64 was made under it. The refusal
  now reads "no format takes it again" (the old "its AIR is superseded"
  was untrue of 40).

**The counts [model]:**

| shape | m | query | batching | fold | ALI | DEEP | logup | count |
|---|---|---|---|---|---|---|---|---|
| 39 (blowup 32, 24 queries) | 5 | **82.70** | 82.79 | 82.98 | 108.38 | 97.68 | 111.60 | 146 / 82 (82.6999) |
| (c) at 28's parameters (shape B) | 4 | 82.60 | **81.74** | 81.93 | 107.70 | 97.00 | 111.60 | 146 / 81 |

- every unmasked format's pinned bits unchanged: 28 at 146 / 82
  (82.60), 30 106 / 62, 32 108 / 63, 35 104 / 62, 36 96 / 57, 37
  106 / 62;
- the least queries that clear 100 / 80 masked, pinned: blowup 16 PoW 26
  28; blowup 32 PoW 20 / 24 / 26 / 28 25 / 24 / 23 / 22, and 23 at fold
  step 2 or a 2^8 last layer; blowup 64 19 (PoW 26 or 28, fold 2 or 3).
  39's own least is 23 (80.84);
- the interaction PoW does not bind 39 (logup 111.60 with it, above 100
  without it, the count the same);
- **by powers** (DIVERGENCE-012 falling): 39 caps at **76.14** (76.136)
  at blowup 32 and **73.64** at blowup 64, however many queries; only
  blowup 8 reaches 80, at 43 queries. The plan and spike 6b say 76.15 and
  73.65: R's 8 columns add 8 sampled values to the batch by powers
  (`log2(963/955)` = 0.012 bits). The affine count does not see them.

**Docs:** `pvm/proof/SECURITY.md` (39's row, 40 among the retired, the
masked count and what it rests on, DIVERGENCE-011's round list `[3, 3, 3,
2]` and its 0.19-bit margin, DIVERGENCE-012's caps, premise and
fallbacks, the audit's scope); `proving.md` A.4's retired list gains 40
(`doc-fixes.md` 31, its 36 half left for 6.9).

**Tests:** `format_masked_tests.rs` (6: the unmasked counts unmoved and 39's
reference, 39's counts and terms, (c) at 28's parameters, the
least-query grid, the interaction PoW, affine batching needed), and in
`security.rs` the round list `[3, 3, 3, 2]` at `log k = 17` and
`variant_c`'s levels and DEEP doubling. The spike's cost proxies and
printed tables were not ported: they are spike 6b's record.
`cargo test -p vos-pvm-proof --no-default-features --lib`: 96 passed.

**Gates:** `just check` green (1,113 tests, 0 failed).
