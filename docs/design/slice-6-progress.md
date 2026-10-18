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
  - `core-model.md` 14 and 17: requirement 4 is met "by the statement
    (slice 5) and format 39 (slice 6)", and the track's item 9 is struck
    as "masked in slice 6", since format 39 is not built yet.
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

**Gates:** docs only, so no `just check`; no reference to the
draft's old name is left in `docs/`.

### 6.0e: a Rust client on a Kreivo dev chain

Running. It picks the subxt release that reads stable2606-2's metadata,
or the raw JSON-RPC fallback, for 6.17b.
