# Slice 7: progress

The log of build step 7, against `slice-7-mobile.md`. Every number is
tagged [measured], [model] or [est]; the research behind the plan is
`research/slice-7/`.

## Step 7.0: the docs, the picks and two probes

### 7.0: the docs

- **This log,** opened in `slice-6-progress.md`'s shape.
- **`proving.md`:**
  - §8's masking floor: a floor per masked component set by the queries
    (2^12 rows at blowup 2 with 86–87 queries, 2^11 at blowup 4 with 43,
    2^10 at blowup 8 with 29; half for a component with no next-row read),
    not "2^11" (`research/slice-7/device-params.md`);
  - §8's "a real phone, early", and §10's ARM-factor risk, retired by the
    Fairphone 6 run (`research/slice-7/phone-fairphone6-s5kit.txt`);
  - §11's slice-7 rows: M3.9 added (11.5–18 weeks), M4 and M5 as the plan
    builds them (12.5–18 and 22–33.5 weeks, 26–39.5 with word-level
    memory), M6 moved past slice 7 (S1); the total replaced by slice 7's
    52–77 engineer-weeks, up to 83; decision 8 and §10's signature-chip
    row say where M6 went.
- **`core-model.md`:** draft 6, with "Changes from draft 5" naming what
  slice 6 built into it (`338e70df`): slice 6's L8.
- **The decisions:** `owner-decisions.md` (S1–S33) and the plan's
  "Decisions" agree; the plan now names S11's and S25's amendments in
  full (the deposit released on `Ended`, `member` without an epoch) and
  the vectors S10 changes in part (G1, G18).

### 7.0a: the device baseline on today's AIR

**Built** (`spikes/s7-device`, throwaway):
- **`guest/`:** a test actor whose attestable `auth` is the statement:
  the member's row in a vos-tree of 10^6 rows (BLAKE2b, salted values,
  the agent root's format) checked against the map's root from its
  encoded multiproof, its value committing to the secret; the output the
  nullifier for a scope; root, scope and binding `#[public]`, so the
  io-hash states them as pin I's auth words do. Derived as a node derives
  it, arguments through the witness input: **19,192 steps**, one segment,
  981 B of input, a 795 B path [measured]. Slice 5's kernel took 12,951
  steps on the pre-hardening AIR with arguments in memory.
- **`harness/`:** the kernel traced by `trace_kernel` and proved whole by
  `prove_shaped` at the run's natural log sizes, under a format the
  process admits under the device number (37): the Blake2s channel, the
  cell's blowup, queries and PoW, interaction PoW 8. Shapes:
  - `built`: the derived shape's 23 chips, verified by
    `verify_standalone`;
  - `floor`: the page-Merkle boundary chips out, the memory ledger's
    boundary entries for accessed bytes only (slice 5's floor seam): pin
    J's shape as a cost proxy (its relations do not balance; not
    verified); 19 chips;
  - `lean`: the floor without BLAKE2b and its AND table, lever 1's shape
    without the Poseidon2 chip that replaces them; 17 chips.
- **The masked-cost proxy:** `masked0` commits every chip one log size
  up (so the composition two up), as the plan states it; `masked12` and
  `masked11` first pad every chip to the floor masking (c) needs at the
  cell's parameters (2^12 at 86 queries, 2^11 at 43). Chips whose size
  their content fixes (the tables, the program, the 16-row boundaries)
  refuse another size and stay: the harness counts what (c) would commit
  with them padded and raised too, and the proxy holds 98–99% of it.
- **`pvm-proof.patch`,** applied only in the copy of the tree
  `scripts/tree.sh` exports (never in the repository): the Blake2s stack
  routed in `with_stack!`, a format the process installs under a
  registered number, and the memory chip's floor seam.

**The proxy, read right** (the review's L11): it raises the trace heights,
so it pays the doubled evaluation domain in full, the Merkle hashing of
the doubled leaf layer included, and constraint evaluation over twice the
rows. It omits what masking adds beyond the domain: the randomizer's
sampling, the salts, R2's blinding, the FRI mask's columns and R1's
retries, and the wrap's lifting. A floor on the masking factor, not an
estimate.

**Measured on x86** (Core Ultra 7 155H, glibc; 4 threads pinned to four
P-cores, 8 threads over the six P-cores' twelve; median of 5; the machine
shared with another agent, load 1.2–5.2, so ±10% and one cell noted)
[measured, `spikes/s7-device/runs/x86.jsonl`, `x86-lean.jsonl`]:

| cell | 4 threads | 8 threads | peak (4) | bytes | columns | cells |
|---|---|---|---|---|---|---|
| built, 1:86:20 | 1.77 s | 1.95 s | 2,280 MiB | 3,538,744 | 7,821 | 142.9M |
| built, 1:86:20, masked0 | 4.00 s | 3.52 s | 4,730 MiB | 3,582,718 | | 285.2M |
| built, 1:86:20, masked12 | 4.23 s | 3.69 s | 4,728 MiB | 3,585,415 | | 300.4M |
| built, 2:43:20 | 2.62 s | 2.69 s | 3,439 MiB | 1,893,890 | | 142.9M |
| built, 2:43:20, masked0 | 5.33 s | 4.56 s | 7,079 MiB | 1,926,827 | | 285.2M |
| built, 2:43:20, masked11 | 5.38 s | 4.73 s | 7,088 MiB | 1,928,527 | | 291.2M |
| floor, 1:86:20 | 0.63 s | 0.59 s | 815 MiB | 2,245,957 | 4,975 | 47.9M |
| floor, 1:86:20, masked0 | 1.31 s | 1.09 s | 1,517 MiB | 2,286,097 | | 95.2M |
| floor, 1:86:20, masked12 | 1.33 s | 1.08 s | 1,596 MiB | 2,292,090 | | 99.6M |
| floor, 2:43:20 | 0.81 s | 0.86 s | 1,251 MiB | 1,217,153 | | 47.9M |
| floor, 2:43:20, masked0 | 1.74 s | 1.54 s | 2,400 MiB | 1,235,889 | | 95.2M |
| floor, 2:43:20, masked11 | 2.73 s (runs 1.75–3.68, under load) | 1.57 s | 2,409 MiB | 1,243,059 | | 96.1M |
| lean, 1:86:20 | 0.48 s | 0.54 s | 642 MiB | 948,004 | 1,882 | 34.9M |
| lean, 1:86:20, masked12 | 0.89 s | 0.82 s | 1,245 MiB | 988,651 | | 73.9M |
| lean, 2:43:20 | 0.63 s | 0.58 s | 970 MiB | 536,273 | | 34.9M |
| lean, 2:43:20, masked11 | 1.18 s | 1.00 s | 1,881 MiB | 561,297 | | 70.5M |
| built, 2:38:20 (the kit's) | 2.62 s | 2.32 s | 3,519 MiB | 1,707,149 | | 142.9M |
| floor, 2:38:20 (the kit's) | 0.84 s | 0.73 s | 1,242 MiB | 1,094,992 | | 47.9M |

Configurations are log blowup : queries : PoW. Cells count every committed
column (preprocessed, main, interaction) times its rows, before blowup.

- **Today's AIR against slice 5's:** at the kit's configuration the floor
  proves in the same 0.84 s (4,975 columns against 4,655), the built shape
  in 2.62 s against 1.72 s (more steps: the witness-input prologue, the
  return's encoding and the io-hash).
- **Verified:** every built proof at 86, 87 and 43 queries, in 21–37 ms
  on x86. The kit's 2:38:20 is refused by today's verifier before any
  cryptographic work: 96 conjectured bits, under the floor of 100.
- **Threads:** 8 threads run from 10% slower to 20% faster than 4 on this
  shared machine; the phone's split is P1's.

**The masked proxy's factor** (proxy over plain, same cell, median)
[measured]:

| shape | 1:86:20, masked12 | 1:86:20, masked0 | 2:43:20, masked11 | 2:43:20, masked0 |
|---|---|---|---|---|
| built | ×2.39 (4) / ×1.89 (8) | ×2.26 / ×1.81 | ×2.05 / ×1.76 | ×2.03 / ×1.70 |
| floor | ×2.09 / ×1.84 | ×2.07 / ×1.86 | ×3.37 (noisy) / ×1.84 | ×2.15 / ×1.80 |
| lean | ×1.85 / ×1.52 | | ×1.89 / ×1.73 | |

So the masking factor on this shape is **at least about ×1.8–2.1** (×1.5–2.4
over all cells), with the cells ×2.0–2.1 and peak memory ×1.9–2.0. The
wrap's measured ×2.6–2.9 is the reference for what masking adds beyond
the proxy; on the segment chips the factor lies between, at ×1.8–2.9
[est].

**Blowup 2 against 4:** at the device candidates, blowup 2 with 86
queries proves in ×0.75–0.78 of blowup 4 with 43 (floor and lean,
plain and proxy, 4 threads), against slice 5's ×0.8 [measured].

**Bytes against pin J's 1.5 MiB (1,572,864 B)** [measured; postcard]:

| shape | 1:86:20 | 1:87:20 | 1:86:20, proxy | 2:43:20 | 2:43:20, proxy |
|---|---|---|---|---|---|
| built | 3,538,744 (×2.25) | 3,577,588 | 3,585,415 | 1,893,890 (×1.20) | 1,928,527 |
| floor | 2,245,957 (×1.43) | 2,271,916 | 2,292,090 | 1,217,153 (×0.77) | 1,243,059 |
| lean | 948,004 (×0.60) | | 988,651 | 536,273 (×0.34) | 561,297 |

- **On today's floor, blowup 2 does not fit:** 2.25–2.27 MB at 86–87
  queries, ×1.43 the budget before masking. Blowup 4 with 43 fits (1.22
  MB) unmasked; masked at the wrap's ×1.31 it would be about 1.6 MB
  [est], just past it.
- **Without BLAKE2b** (lever 1) blowup 2 fits: 0.95 MB, about 1.1 MB with
  the Poseidon2 chip's ~300 columns [est], 1.1–1.45 MB masked (the proxy's
  ×1.02 to the wrap's ×1.31) [est]. So pin J's blowup-2 candidate depends
  on lever 1 landing first.
- The proxy adds 1–2% to the bytes (one more Merkle level a path); the
  masking's own columns and salts are what the wrap's ×1.31 measured.

**The PoW grind** (Blake2s-M31 channel, 128 grinds a cell, x86)
[measured]: PoW 20 median 40 ms, 95th percentile 48 ms on 4 threads (63
and 79 ms on 8, under load); PoW 16 5 and 12 ms (8 and 16 on 8). On the
phone about 0.12–0.14 s median at PoW 20 [est, ×3–3.5], inside every
proving time above and untouched by the levers.

**Peak memory against pin J's 1 GiB:** the masked floor needs 1.5–2.4 GiB
on x86, the masked lean shape 1.25 GiB at blowup 2 (1.9 GiB at 4); the
phone's mimalloc build runs about 15% above [measured, slice 5]. Memory
tracks the cells, so the CPU-side levers (3, 6, 5) bring it under 1 GiB
only together: about 0.5–0.75 GiB after levers 3 and 6 [est].

**Phone binaries** (session P1): `spikes/s7-device/phone-dist/`,
`s7-phone-timing` and `s7-phone-seeded`, static aarch64-musl, 9.0 MB each
(SHA-256 in `s7-phone.sha256`, the x86 proofs' in `x86-references.txt`),
built by `scripts/phone.sh`; the runbook is `phone-dist/runbook.md`.
Under qemu-aarch64 every P1 cell's proof from the seeded build is
byte-identical to x86's and the built proof verifies; the timing build's
proofs too (nothing is masked in 7.0a) [measured,
`runs/qemu-seeded-p1.jsonl`, `runs/qemu-timing.jsonl`].

**On the phone:** pending P1.

**M5's outlook, redone** [est, from the x86 cells above and slice 5's
phone ratio; P1 replaces the ratio]. The phone at automatic threads is
taken at 2.6–3.0× x86 on four P-cores (the kit's: built 5.1 s against 1.72
s, the floor 2.2 s against 0.84 s). The grind (about 0.13 s) is taken out
before the levers' factors and added back:

| | factor | time on the phone | basis |
|---|---|---|---|
| today's floor, masked proxy, blowup 2, 86 queries | | 3.5–4.0 s | x86 1.33 s [measured] |
| lever 1: BLAKE2b and its AND table gone (the lean shape) | ×0.67 | 2.3–2.7 s | x86 0.89 s [measured proxy]; the Poseidon2 chip not counted |
| masking beyond the proxy | ×1.0–1.4 | 2.3–3.7 s | the proxy ×1.8–2.1 is a floor, the wrap's ×2.6–2.9 the reference |
| lever 2: threads by core class | ×0.9 | 2.1–3.4 s | [measured, slice 5: 2–9%] |
| lever 3: a lean kernel | ×0.55–0.7 | 1.2–2.4 s | [model, slice 5] |
| lever 6: the CPU split | ×0.65–0.75 | 0.8–1.8 s | [model] |
| lever 5: word-level memory | ×0.88–0.92 | **0.75–1.7 s** | [model]; the grind's 0.13 s included |

- **Against the old outlook** (0.7–1.5 s): the favourable end holds; the
  unfavourable end rises to about 1.7 s, the blowup-2 gain being in the
  starting cell already and the masking's factor still a range. **1 s
  remains reachable only at the favourable end, after levers 1–3 and the
  CPU split**, as draft 4 said.
- **The 95th percentile** adds about 0.05–0.2 s of grind tail [est]; PoW
  16 (95 queries at blowup 2, about 10% more bytes) makes the grind about
  0.02 s.
- **Two more constraints the cells show:** the blowup-2 candidate fits
  1.5 MiB only once BLAKE2b is gone; peak memory under 1 GiB needs the
  CPU-side levers, not only lever 1.
- **For the owner (S20):** after P1 measures the ratio on today's AIR, the
  gate stays at ≤ 1 s or is set from the measured range.

### 7.0b: the secret sources on the gate device

Pending P1.

## Step 7.1: the venue side simplified

C6, C1, C4, C8 and C7 (pin D′) at every venue, from vos-core `8b6c9d34`.

**The venue core** (`pvm/proof/anchor/src/venue.rs`, `no_std`): the
registration (`registration`, stateless: 1–16 distinct founding keys, none
of small order, a registrable clock, the founder's strict signature over
`register_digest(venue, space, controller)`; then `register`: a new space,
its first window the venue's next), the anchor rule (`anchor`, answering
`New`, `Again` or `Evidence(held)`, or one of seven refusals), `anchored`,
`expiry`, `fresh`, `aged`, `seen_expiry` and `small_order`, over two
traits (`Roots`, `VenueState: Roots`). Its suite (`vos_anchor::suite`,
feature `suite`) states every rule and refusal once against a `Harness`;
it runs against `ModelVenue`, the Kreivo mock (as a pallet) and the JAM
service (natively, over its storage).

**Every venue calls it:** `ModelVenue` (registration, anchor, anchored);
the Kreivo mock (registration, anchor, anchored, `on_idle`'s `aged`); the
JAM service (refine's registration, accumulate's register, anchor and
anchored over a `Snapshot`); `vos-statement`'s model policy (anchored);
the Kreivo client and jam-dev's client (anchored over what they read). The
`check-venue-rules` recipe, in `just check`, refuses the rule's arithmetic
(`MAX_ROOT_AGE_MS`, `.boundary(`, `verify_strict`, `SMALL_ORDER`) in any
venue's non-test source outside the two verifiers the core is handed, and
requires each venue's call to the core.

**Removed:**
- **Migration (C1):** `Migrate` and `migrate_digest`, `ModelVenue::migrate`,
  the mock's `migrate` (call 5, `end_window`, errors 18, 24, 28, event 5),
  the service's migrate item (tag 1), jam-dev's `migrate`, the e2e's
  migration leg and its `Migrating` client.
- **Resume (C4):** `ModelVenue::resume`, the mock's `resume` (call 6, error
  23, event 9, unblock to `Suspended`), the service's `Resume` control
  (op 2) and its `Suspended` state; slice 6's F3 with them. An equivocation
  now ends the space: status `Ended` (Kreivo index 3, 1 retired), the
  evidence stored, the first root's record kept, the registration deposit
  released, `dispatch_as_sovereign` still callable; the record a tombstone,
  so a replayed registration is `SpaceExists`.
- **A signed start window (C8):** `register_digest` loses `start_window`;
  the mock's `BadStartWindow` (26) and the service's range codes go. The
  space anchors from `now_w + 1` (window 0 before its origin).
- **Rootless and venue-bound statements (C7):** `Pin`, `venue_bound`,
  `Refusal::Venue` (7, retired), the `Venue::id` judge input, the rootless
  `Seen` rule, `wrap-rootless.proof`, the final verifier runner's
  `statements` mode, and their tests and fixture cases.
- **The Kreivo client's anchor-rule checks** (slice 6's F2): `behind()`
  and the window and age checks on the batch thread. The client checks no
  anchor rule; its reads of the space's status, the pause and the listed
  keys stay, as pin D′ keeps them, and spare a fee (`WindowInFuture` →
  again a block later; `Landed` → the record read back).

**Folded:** L4 (strict ed25519 everywhere; a small-order key refused at
registration as `BadGenesis` and when added as `BadAnchorKey` (30), the
G14 and G17 vectors); duplicate founding keys `BadGenesis`; the service's
storage read trapping on an undecodable row (`Storage::corrupt`, a test);
`add_authority` of an authority already `AuthorityExists` (29); item 74
(`vos_venue::forward_venue!`, six wrappers: `Tapped`, `Recorded`,
`Judging`, `Watched`, `Unread`, `Queued`; the seventh, `Migrating`, is
gone); item 29 (the service's control tests split by concern).

**Lines** (`git diff --numstat` from `8b6c9d34`, sources and tests):

| crate | added | removed |
|---|---|---|
| vos-anchor | +748 | −101 |
| vos-statement | +158 | −355 |
| vos-statement-service | +884 | −909 |
| vos-venue | +1,437 | −1,635 |
| vos-node (src) | +14 | −18 |
| vos-node (tests, the e2e among them) | +390 | −676 |
| vos-checker | +4 | −28 |
| vos-jam-dev | +186 | −304 |
| vos-pvm-proof tests | +45 | −238 |
| the fuzz targets | +16 | −34 |
| the final verifier's runner | +1 | −22 |
| the conformance vectors (JSON) | +1,951 | −3,138 |
| `spaces-pallet.md` and other docs | +286 | −247 |

Of vos-anchor's added lines, the core is 345 and its suite 315.

**The vectors, regenerated once:**
- `spaces.json`: G1–G19 → G1–G17 (182 steps → 150). v1's G14 (`migrate`)
  and G19 (`resume`) gone; G15–G18 renumbered G14–G17. Every vector's
  bytes changed (`SpaceInfo` lost `end_window`, `ProgramInfo`
  `venue_bound`); G1, G4, G5, G7, G9, G11 and G14–G17 changed scenario.
  The constants lose `max_root_age_ms`, `min_window_ms`, `max_window_ms`.
- `mutations.json`: the same 416 mutants; those that reached code 7 now
  reach the proof's codes (`0x108`, `0x109`).
- `statements.cases` (19,179 → 14,591 B; the proofs byte-identical):
  "another venue's statement", "replayed at another venue", "migrated
  before a root's window", "registered after a root's window" and the
  rootless replay gone; "rootless, another space" is "rootless" (refused
  4); the rooted replay is "replayed past MaxRootAge". `wrap-rootless.proof`
  (146,052 B) deleted.
- `just conformance` regenerates both files byte for byte.

**Unchanged:** the node's kernels and the agent image
(`the_program_ids_are_the_repositorys` and the pinned image tests pass;
no file under `agent/` or the kernels changed). The statement service's
blob changed, as expected.

**The e2e** (`just e2e-chain`) [measured]: two spaces of three nodes,
one at the Kreivo mock and one at JAM `a`, each registered from window 1;
seven statements accepted at their venues; the JAM space's first statement
refused 5 at Kreivo and at JAM `b`; the reader's rootless `ordered`
refused 4 at JAM `a`; replayed past `MaxRootAge`, 5. Latency 51.7 s at
Kreivo, 85.4–132.9 s at JAM, every one under its gate (189.9–207.7 s);
refine about 79.2–80.3 M gas a statement; Kreivo's sovereign charged 11.5
UNITS (9 anchors, 2 submits, one deposit forfeited); the audit clean over
398 carriers; 1,051 s.

**Gates:** `just check` (the new `check-venue-rules` in it) green; `just
conformance` byte for byte; `just e2e-chain` green.

**Where the plan was off:**
- The fixtures' `statements.cases` regenerated here, not first at 7.8a:
  the policy's encoding lost the venue and the cases with it. Only the
  cases file changed; the proofs are byte-identical, so the program ids
  and the kit's proofs hold.
- The e2e could not keep one space across both venues once migration
  went: it runs two spaces, one at each.
- C2's half on the pallet (an authority's key set once, `AuthorityExists`)
  landed here, so the vectors regenerate once; the node's side stays 7.2's.
- `BadClock` before the origin and `OutOfRange` merged into the core's
  refusals: an anchor before the space's first window is
  `WindowNotAfterLast`, one before its origin `WindowInFuture`.

### The review's fixes

Fable's review (`research/slice-7/7.1-fable.md`: fix, then merge), folded
as further commits:
- **M1:** the anchor rule judges a window's age before its held root, so
  a second root at an aged window is `Age` whether or not the venue has
  pruned the first; only a fresh window's second root is evidence. A suite
  case pins it at the three venues. `spaces.json`'s G4 changed (its stale
  and before-the-first refusals had sat at aged windows; they now sit at
  fresh ones, and G4 gains the aged second root, `WindowTooOld`, the space
  active); G5, G16 and every other vector are byte-identical, and
  `mutations.json` is unchanged.
- **M2:** `proving.md` (§3.6's statement rules, §6's venues, §7's
  equivocation and one venue, A.6's fixture tables) and
  `clerk-across-spaces.md` follow pin D′.
- **M3:** one venue a space is the space's discipline, which no venue
  enforces: a founder may register the same genesis at two venues, and
  with the same roots a statement is handled at both, with different
  roots the space forks unseen. Stated in `vos-statement`'s crate doc,
  `spaces-pallet.md` §0, §6.2 and §6.3, pin D′'s C1 bullet and
  `simplify.md` C1 (an erratum).
- **L1:** JAM's refine judges an anchor's signature before the state
  checks; a suite case takes an anchor failing both its key and its
  signature as refused by either, and refine's doc and `spaces-pallet.md`
  §6.1 say so.
- **L2:** the key-listing rule is the core's `venue::add_key` (small order,
  listed, at most `MAX_FOUNDING_KEYS`), which the model, the service's
  `AddKey` and the mock's `add_authority` call; a suite case fills a space's
  keys; the mock's `MaxAnchorKeys` is the kit's constant.
- **L3:** `check-venue-rules` also refuses `registrable`, the window
  lengths, the key bound, `small_order(` and comparisons with the last
  window anchored, now over jam-dev's commands too, and requires each
  venue's `add_key`. It caught the two clients' settled check comparing
  with the last window itself; both now ask the core (`venue::passed`).
  The clients' sanctioned status and key reads are not flagged.
- **L5:** the record's line on the Kreivo client corrected (above).
- **L6:** `spaces-pallet.md` §9's rotation and hand-back language left for
  7.2's doc pass.
- The statement model's policy says why its spaces read active from window
  0.

**Not to run alone (L4):** until 7.2, the representative's leader signs its
own cut's root (`node/host/src/leader/anchor.rs`), with no replicated
anchor row and no divergence guard. A deposed leader whose close was not
committed and a successor can sign two roots for one window: under 7.1
that honest double-sign ends the space for good. 7.1 lands with 7.2, never
alone, before any space whose state matters runs on it.

**Gates after the fixes:** `just check` green (`check-venue-rules`: 44
files, 18 calls); `just conformance` byte for byte; `just e2e-chain` green
again [measured]: 1,036 s, the same verdicts, latency 47.5 s at Kreivo and
60.8–109.0 s at JAM, each under its gate; the audit clean over 398
carriers.


## Step 7.4: the scale harness

**Built:**
- **`tools/scale` (`vos-scale`):** a development crate that no shipped
  crate depends on. The `check-no-scale` row, part of `check-no-leaks`,
  refuses it in `vos` (with and without the prover) and in `vos-node`.
  An `inventory.toml` drives it, with one `[[host]]` for each node or
  driver: ssh target (or `localhost`), LAN address, role, weight, data
  directory, cores, and the ingress and peer ports. Commands:
  - `check`: reads every host with one script, and its clock with five
    `date` reads (the shortest round trip wins). It refuses another
    architecture, a kernel before 6.7 (unless `old_kernel` is set, the
    host weighted down), a clock more than 100 ms off, Wi-Fi, missing
    tools, a taken port, no user manager, and, over ssh, no lingering.
    It warns about a governor other than `performance`, a rotating data
    disk, and a link under 1 GbE or of unknown speed. It records link
    speed, governors, disk, transport and model with every run.
  - `deploy`: refuses a binary that is not a static x86-64 one, then
    ships `vos`, `vos-scale` and the agent by `rsync`. Each node's first
    run makes its key, and the shell that started the node stops it by
    its PID. The tool writes the space file, the first node founds the
    space, and the genesis goes to every node. Versions are kept:
    `vos --version`, the revision and each artifact's SHA-256.
  - `up` and `down`: each node and each host's sampler run in a
    `systemd-run --user` unit with `MemoryMax`, no swap,
    `LimitNOFILE=65536`, and optional `taskset`. They are stopped by unit
    name only, never by process name. Ingress uses `--tls` with the node
    key pinned, so the harness makes no certificates.
  - `agents`: places three replicas per agent by weight (seeded, no
    replacement), creates each agent, and installs it at whichever
    replica leads. `--representative` creates the representative first.
  - `drive`: one `vos-scale drive-local` unit on each driver host, each
    taking its share of the users and of the rate. Meanwhile the
    coordinator polls `/stats` and every replica's status.
  - `collect`: copies each host's samples, node log and driver record
    into the run's directory.
  - `report`: one directory per run, holding the inventory, host facts,
    versions, agents, polls, samples, `summary.json` and `report.txt`.
    For each host it gives the binding resource (the node's CPU against
    its cores, iowait, disk busy time, the NIC against its link speed),
    the busiest threads, RSS and idle wakes. It also gives the nodes'
    stage quantiles, leader changes and the drivers' p50, p99 and p99.9,
    and names the slowest node host. Every report states what it does
    not model and T2's assumption (K ≥ 128 for 8 million users).
    `--compare` sets two runs side by side.
  - `run`: deploy, up, agents, drive, collect, down and report, all from
    one command. `--exclude NAME` reruns without a host.
  - `sample`, run on each host, writes a JSON line every 10 s: the
    host's CPU by kind, the node's threads (ticks, voluntary switches),
    RSS, I/O, the data disk's counters and the link's bytes. It finds the
    node by its unit's main PID.
- **The smoke load** is `drive`'s: one method, users drawn uniformly,
  open loop with Poisson arrivals, latency timed from the scheduled send,
  and one client per active user. 7.5 replaces it.
- **Node changes:**
  - `vos node run --config node.toml` sets `executors`, `queue`,
    `max_inputs`, `max_bytes`, `linger_ms`, `ingress_connections`,
    `election_timeout_ms` and `heartbeat_ms`. Unknown names are refused,
    and so are unsound timings.
  - The admin route `POST /representative`, with
    `Operator::create_representative` and `vos space representative`.
  - Slice 6's L3: `default-members` leaves out the checker, jam-dev and
    the harness, so a plain `cargo build` resolves `vos` without `dump`,
    `kreivo` or `fixtures`.
  - `just release`: the static musl builds of `vos` and `vos-scale`,
    `--locked`, not incremental, each built on its own.
- **A fix the static build needed:** the PVM's write tracker typed its
  `ioctl` requests as `c_ulong`, which musl refuses. They are now
  `libc::Ioctl`, with the same 32 bits.
- **The owner's runbook:** `tools/scale/README.md`, with
  `inventory.example.toml` beside it.

**Tests:**
- The inventory: shipped files read; clashes refused.
- `check`'s verdicts: Wi-Fi, old kernel, skew, arch, linger, tools,
  ports refused; slow link, HDD, governor warned.
- Unit scripts: cap, stop by name, no process matching.
- Placement by weight; the ELF check; the sampler's parsers on this host.
- Histograms; the binding resource; the report's two statements.
- The node's settings file.
- A CLI test: `--config` refused and accepted, the representative
  created once.

**The localhost smoke** [measured,
`/var/tmp/vos-scale/runs/20261025T110039Z-smoke`,
`20261025T110145Z-without-n3`]:
- **The setup:** `tools/scale/inventory.localhost.toml`, with four nodes
  and a driver on this machine, each on its own cores, ports and
  directory.
- **The command:** one `vos-scale run --agents 4 --representative
  --users 40 --rate 20 --secs 30`.
- **The run:** a space founded, four nodes up behind pinned TLS, the
  representative and four counter agents placed, 587 calls answered and
  no errors (19.6 a second), no leader change.
- **Every unit stopped,** and the report written.
- **The rerun:** `--exclude n3`, then `report --compare`, ran end to
  end.
- **The numbers mean nothing for scale.** The four nodes share one NVMe
  (95% full) with other agents' builds, and the governor is
  `powersave`, which `check` warned about. The driver's p99 went from
  1.05 s with all four nodes to 20 ms without n3. The first run saw the
  shared disk at 38.8 ms per I/O and a commit p99.9 near 1 s, and n3 was
  no slower than the others. So the difference is not shown to be n3's;
  the shared disk is the likely cause, but this run cannot establish it.
- **The first smokes** (three nodes, then four) ran the same way.

**Gates:**
- `just check` green: `check-no-leaks` with the `scale` row, 104
  suites.
- The localhost smoke, above.

**Left for the owner and later steps:**
- **Not run:** no remote host was contacted, and none was given.
- **7.4's gate** (three hosts, 100 agents, 10,000 users, on two of the
  owner's machines at least) needs the owner's inventory. For that many
  users at once, `[node] ingress_connections` must go up, because the
  smoke driver gives each active user its own client and connection. The
  connection model (users multiplexed over a few connections, calls
  signed ahead) belongs to 7.5's drivers.
- **The representative in a run** creates and installs; anchoring
  stays 7.2's.

### The review's fixes

The Opus review said fix, then merge, and that the harness must not run
on the owner's machines until the fixes land. They are folded here as
further commits.

**High:**
- **H1, the wipe:** `dir` is now an absolute path of plain characters,
  with no empty, `.` or `..` part. It must be at least two levels deep and
  not a home directory, and no entry's dir may sit inside another entry's
  on the same machine. On the host, a deploy refuses `/` and `$HOME` (after
  following links). It makes `dir` only when it is absent or empty, and
  marks it `.vos-scale`. It wipes nothing in a dir that holds other files
  and no marker. Tests cover each refusal; the guard script is run on temp
  dirs, links included. The smoke showed it working: my earlier unmarked
  dirs were refused and left untouched.
- **H2, the clock:**
  - The offset is now measured as a ping-pong over one ssh session
    (`while read; do date +%s%N; done`), keeping the read with the
    shortest round trip of eight. Localhost reads 0.4–0.5 ms, against
    0.9–2.0 ms before.
  - `check` records NTP sync (`timedatectl`) and chrony's offset, and
    warns when sync is unknown or off.
- **H3, a saturated thread:** the busiest single thread (by tid, as a
  share of one core) is now a candidate for the binding resource. A test
  shows a thread at 95% binding on an otherwise idle host.

**Medium:**
- **M1, the driver as bottleneck:** each driver now counts its sends and
  how many went more than 10 ms behind schedule. The report gives each
  driver's worst lateness and late share, and warns above 1% that the
  driver, not the nodes, may have bound the run.
- **M2, the slowest node host:** it is now the host whose node has the
  highest `commit` p99, with the host's disk ms/io breaking ties. Nodes
  are mapped to host names, and the binding resource stays as a per-host
  label.
- **M3, memory and placement:** `check` groups entries by machine (its
  machine id, else its ssh host). It refuses a machine whose entries' caps
  plus a 2 GiB reserve exceed its free memory. It also refuses a node's
  machine that holds a driver or the coordinator, unless
  `harness.smoke = true`, in which case it only warns. The localhost
  inventory sets `smoke = true`.
- **M4, leftovers:**
  - The first run is wrapped in `timeout 60`.
  - Every unit has `RuntimeMaxSec`: `harness.max_run_s` (6 h by default)
    for nodes and samplers, and the load plus 5 minutes for drivers.
  - `down`, and `deploy` before it ships, stop units on every listed
    entry, excluded ones too. An unreachable excluded host is only warned
    about.
  - `run` stops every unit when deploy fails, when it fails partway, and
    on SIGINT or SIGTERM: the handler sets a flag, and every wait and
    poll ends on it. Tested: an interrupted run went from 10 units to 0.
- **M5:** every remote script runs under `timeout 300 bash -s`, and each
  clock session under `timeout 60`.
- **M6:** the runbook and the report now say that a rerun without the
  slowest host needs four node hosts or more. The report warns when it has
  fewer.

**Low:**
- **L1:** `ssh` must be `localhost` or `[user@]host` of plain characters,
  with no leading `-`. `address` must be an IP address.
- **L2:** `--config` refuses a zero for `queue`, `max_inputs`,
  `max_bytes` and `ingress_connections`, as it already did for
  `executors`.
- **L3:** the justfile's comments are back in place: `install-hooks`
  keeps its own, and `check-no-scale` sits with the other `check-no-*`
  gates.
- **L4:** the report's default window is the drivers' span, measured with
  the run's `every_s`, minus a ramp of one interval at the start
  (`--ramp-s` sets the ramp).
- **L5:** `/stats` now carries `groups` (replicas, leading, the sum of
  terms), with a host test. The poller records it, and the report gives
  each node's leaders and elections in the window.
- **L6:** `check` warns about a USB or unknown data disk, and labels an
  unknown transport `?` instead of `ssd`. Hosts sample their cores' clock
  against its maximum, and the report gives it as `clock%`, warning when a
  node ran below 70%.
- **L7:** a process's CPU now comes from the totals in `/proc/<pid>/stat`.
- `vos-scale` now uses mimalloc, as `vos` does.

**The smoke again** [measured, `/var/tmp/vos-scale/runs/20261025T112914Z-smoke`
and `20261025T113050Z-without-n3`]: one `run` with 4 agents, the
representative, 40 users and 20 calls a second for 40 s, on four nodes and
a driver.
- **First run:** 797 calls answered, 0 errors, 0 elections.
- **The new warnings fired as they should:**
  - The driver was flagged, with 13.6% of its sends more than 10 ms late
    and 11.5 s at worst, because the shared disk stalled commits for
    seconds (disk 44–46% busy, 41–47 ms per I/O).
  - The nodes' cores ran at 25–29% of their top clock under `powersave`.
  - Every entry was flagged as sharing one machine, a smoke only.
- **Rerun without n3:** 797 calls, 0 errors, p99 57 ms, 0.38% of sends
  late. `report --compare` set the two runs side by side.
- **What the numbers mean:** on this shared machine they are a
  smoke's, not a measurement.

**Gates after the fixes:** `just check` green, 104 suites, the new stats
test among them; the localhost smoke, the interrupt and the rerun, above.

## Step 7.8a: the pvm-internal re-pin

Slice 6's carried items inside `pvm/proof`, the final verifier, recair and
the kernels' code, from vos-core `62981f95`, each its own commit, and one
re-pin at the end.

| item | what | commit |
|---|---|---|
| 13 | the masking's witness digest hashes `statement_header_words` (its count first), then the words the header leaves out: the DEEP batching, the interaction PoW, the channel, the masking | `40614908` |
| 16, unmasked half | `unmasked::check_samples` by `masked::samples_fit`; `check_shape`'s four tree counts one array | `d4ea3be8` |
| 17 | `vos_pvm_recair_air::evals`, shared by `Components::new`, `WrapComponents::build` and `bind`, the allocation order kept; `WrapComponents::layout`, the dummy layout the final verifier and three tests laid out by hand | `f6653134` |
| 18 | `replay`'s seams `admitted` and `check_composition`, the check order kept; `masked::eval_lifted_composition`, for the final verifier and recair-air's tests | `6d979de2` |
| 19 | `recair-air/src/masked.rs` split into `masked/{mod,component,wrap}.rs`; `masked::TREES` once, the final verifier re-exporting it, `sample_points` reading `TREES − 1` for the literal 3 | `b74d2124` |
| 20, `final-verify.elf`'s piece | the guest's mode bytes a `#[repr(u8)] Mode`, its verdicts a `#[repr(u64)] Verdict`; the wire and the report unchanged | `ccb8ca81` |
| 24, `final-verify.elf`'s piece | the guest's `verify` split: `vectors`, `lookup_proof`; one `Request<J>` for `Request` and `Check`; the words decoded without the copy | `41b97e0d` |
| slice 5's 18, `array::from_fn` | `agent/tree`'s branch hash builds its child words by `array::from_fn` over `as_chunks`; every guest ELF byte-identical | `a2e4648c` |
| slice 5's 18, `leaf_terms` | the per-query and OODS offsets named after the pieces of recair's verifier they count: `domain_point_rows` (`4L − 5`: 2 for the bit above the first, 4 a bit after, 1 to conjugate; `verifier::circle::domain_point`), `fri_fold_rows` (`6F − 2`: 5 a layer, the twiddle's inverse, the difference, its scaling, the sum and the fold, and `x` doubled past the second; `verifier::fri::verify_query`), `OODS_ROWS` (15: the point from its draw 4, the shift 2, the vanishing inverse 1, the composition's halves 3 each, their sum 1, the product 1; with the two doubling chains `2(m − 1)`, the old `2m + 13`), `PREPROCESSED_ROOT_WORDS` (the shape's `+ 2`); every count unchanged | `9c0037a9` |
| the re-pin | `just fixtures`, `just conformance`; `proving.md` and `recursion-air.md`'s `wrap.proof` size | `0de5ebcb` |

**Left to 7.8b, as the plan splits them:** items 3, 4's guest half, 21,
22, 23 (the guests' shared runtime: `statement-service.elf` includes it),
25 and the service's and `vos-anchor`'s pieces of 17–24, 26
(`SpaceGenesis::version`), 27 (`ANCHORS` out of `final-verify.elf`), 28
(`read_nat`), 33, 64–67, 69 and `blobs.lock`. Item 18's fourth copy, in
recair's `prove_once`, stays: the prover keeps the lifted set for R1's
rank check, so the shared evaluation would lift it twice.

**The pinned values:** none of `pvm/proof/src/constants.rs` moved.
`WINDOW_PROGRAM`, `BALANCE_PROGRAM`, `PREDICATE_PROGRAM`, `H_FOLD`,
`WRAP_ROOT_28` and `WRAP_ROOT_39` are as at `62981f95`:
- the program ids: every guest ELF (the 22 test actors, the agent image,
  the representative) is byte-identical to `62981f95`'s, so no kernel's
  program id moves (below, on `array::from_fn`);
- `H_FOLD` and the wraps' roots: the fold and wrap circuits are recair's
  compilation of the segment verifier, which no item changed, and items
  17–19 keep the wrap AIR's allocation order, so its preprocessed tree is
  the same.

**What moved:**
- The fixtures (sha256 prefix, bytes): `wrap.proof` `0b8e3cea…` 146,564 →
  `57f72bf7…` 148,612; `wrap-midway.proof` `d8ffe921…` 145,028 →
  `dda5bf84…` 147,588; `wrap-prefix.proof` `15e5dfbc…` 144,292 →
  `1e2b8860…` 142,724; `statements.cases` `b95ffc54…` → `30649910…`
  (14,591 B, the cases unchanged, the wraps in them the new ones). The
  masked wraps move with item 13: the seeded masks hash the new statement
  words, so other masks, other roots, other query positions and another
  count of decommitted nodes. `segment-35.*` and `wrap-28.proof`
  (unmasked) are byte-identical.
- The conformance vectors: `spaces.json` and `mutations.json`, the wraps'
  hashes and lengths in the submit steps alone; the scenarios unchanged.
- The blobs that link the final verifier change with its code (not
  hashed here; no test pins them, 7.8b's `blobs.lock` will):
  `final-verify.elf`, `final-verify-test.elf`, both Wasm blobs and
  `statement-service.elf`, which links it through `vos-statement`.

**The teammate's second drop:** the kit's fixtures (the three masked
wraps and `statements.cases`), the conformance vectors (the wraps'
hashes and lengths) and the vendored
`vos-pvm-recair-air` (the masked module split into three files, `evals`,
`WrapComponents::layout`, `eval_lifted_composition`, `TREES`) and
`vos-pvm-final-verifier` (`replay`'s seams, `masked::TREES` a re-export).
No pallet code changes: a verifier accepts the old wraps as before, and
the new ones are the vectors'. The pinned program ids are unchanged, so
the drop carries none; 7.21 is the one left that may move them.

**`array::from_fn` and the kernels' steps** [measured]: written as
`from_fn(|k| word(hash, k))` over the old slice-and-`try_into` closure,
the branch hash moved the window, balance, reader and accounts kernels
and cost the sixteen-row read's prologue 16,753 steps (210,019 →
226,772, +8.0%; one row 35,465 → 37,495), past `BUDGET_SIXTEEN_STEPS`'
10% margin (`reads::reads_at_a_cut_measure` failed in `test-proof`):
the per-`k` slice was no longer folded into word loads. Read through
`as_chunks::<8>()`, the same `from_fn` compiles to the old code byte for
byte, so the item lands without moving `WINDOW_PROGRAM` or
`BALANCE_PROGRAM`.


**Where the plan was off:**
- The Fable review's M4 lists 7.8's items as "13, 14, 18, 19, 21–26, 34
  and 35" with `shape::chip`, `chips_of_mask`, the CPU `Lookups`, the
  Blake2b column macro, `MIN_LOG_SIZE` and the `derive::kernel` and
  `DeepPlan::new` splits: that is slice 5's review's numbering, and 6.22
  landed all of it but item 18's two pieces, folded here. The plan's own
  7.8a list (slice 6's numbering) is the one this step followed.
- The plan expected the re-pin to move program ids (`array::from_fn`
  moving `WINDOW_PROGRAM` and `BALANCE_PROGRAM`, slice 6's carried note).
  Written so the guest's code is the same, it moves none: 7.8a's drop is
  fixtures and vectors, no ids.
- `final-verify.elf`'s pieces of items 20 and 24 land here (the plan's
  "final verifier's pieces of 17–25"); 7.8b's item 27 then removes the
  `Anchors` mode and `vectors` from the same file.

**Gates** [measured; each under a 12 GiB scope, `nice -n 10`,
`CARGO_BUILD_JOBS=8`, one heavy run at a time, other agents' runs on the
machine]:
- **`just check`:** green at `0de5ebcb`, 1,400 passed in 109 suites
  (`check-kit` and `fuzz-replay` in it). The first run caught recair's
  `only_the_masked_module_names_the_blinding_relation`, which named the
  file `masked.rs`: it now exempts the `masked/` module (folded into
  item 19's commit).
- **`just test-proof`** (`ci-full`'s: the leakage gates at their medium
  N): green, 562 passed in 47 suites, 3,223 s; `constants::` with every
  pinned value as at `62981f95`; the carrier audit clean (451
  `WrapRandomness` needles). Its first run, with `from_fn` written the
  first way, failed `reads::reads_at_a_cut_measure` (above).
- **`just repro-aarch64`:** the program ids and the circuits' constants
  on aarch64 are the repository's.
- **`just e2e-chain`:** green, 1,071 s: seven statements accepted at
  their venues, the JAM space's first statement refused 5 at Kreivo and
  at JAM `b`, the rootless one 4, the replay past `MaxRootAge` 5; latency
  50.4 s at Kreivo and 72.9–127.0 s at JAM, each under its gate
  (193.1–216.6 s); refine 78.3–80.0 M gas a statement; the audit clean
  over 398 carriers. A first run, under the machine's load at the time
  (load average about 11), failed one latency gate by 2.2 s (JAM's
  window-2 window statement, 228.8 s against 226.6 s) after every verdict
  had come out as expected; rerun at a load of about 4, green.

### The review's fixes

Fable's review (`research/slice-7/7.8a-fable.md`: merge), its four Lows
folded as further commits:
- **L1:** `proving.md`'s `final-verify.elf` gas line labelled as the
  fixture pinned at 6.22 (146,564 bytes), historical (`1dde2ca7`).
- **L2:** `teammate-note.md`'s drops: 7.8a carries the fixtures, the
  vectors' wrap hashes and lengths and the vendored `vos-pvm-recair-air`
  and `vos-pvm-final-verifier` sources, no pinned program id
  (`825dd799`).
- **L3:** the witness digest's unit test also varies the log sizes, the
  format's number and the masks' height, each its own stream
  (`7d7e355f`).
- **L4:** `domain_point_rows` and `fri_fold_rows` state their
  preconditions (`log_size ≥ 2`, `layers ≥ 2`) as `debug_assert!`s
  (`18f57223`).

The two nits (`Mode::of` as a `match`; the test helper's mode byte `[2]`,
which 7.8b's item 27 deletes) are left.

**Gates after the fixes:** `just check` green, 1,400 passed in 109 suites
[measured].

## Step 7.2: the node's anchoring simplified

C2, C3 and C5 (pin D′) on the node, from vos-core `62981f95`, in three
commits and a doc pass.

**The node key alone (C2):** a node signs its space's anchors with its
node key, and replicates the representative while the venue lists that
key. The rotatable anchor keys of 6.14b go: `anchor_keys.rs`, their store
rows (`NodeRow` tag `0x0f`, reserved), the storage change that wrote them,
the rotation API and `vos node anchor-key rotate`, and the leader's
`key_refused` memo.

**One outcome (C5):** every venue client answers an anchor with
`AnchorOutcome { Taken, NotYet, Never(u32), Unlisted(u32), Stopped(u32) }`,
the raw code kept for the log, each client mapping its venue's codes by
one table tested against every code: the model venue's rule refusals
(`model::outcome`), Kreivo's pallet errors (`send::outcome_of`) and the JAM
service's anchor codes (`venue::outcome`). A submit's outcome is
`SubmitOutcome { Accepted, Refused(u32), Retry(u32) }`, a repeat accepted at
one site (`SubmitOutcome::judged`); the prover worker maps it, a venue's
failure to judge still bounded by `MAX_RESUBMITS`, the rest retried until
the anchor ages (C7 left no rootless branch). `AnchorRefusal` (8),
`Anchored` (3), `NotAccepted` (2), `Unjudged` (3), the queue's `Fate` (4 → 2),
Kreivo's `Answer` (7) and `transient` go.

**No hand-back, a replicated row (C3):**
- The representative's close of each window, the commit that finishes its
  cut's build, writes `anchor(w) = S_w` (`keys::anchor`, node-local, the
  same bytes on every replica, kept for `MaxRootAge`). The representative
  keeps two cut roots, as every agent does.
- Its leader signs only those rows, never a root of a batch under
  proposal, in window order, with the node key, before each batch and
  every 2 s while a row waits. A window settles once the client reads the
  venue holding its root, or the venue never takes it; one past
  `MaxRootAge` by the venue's time settles unsent.
- The divergence guard: where the venue holds another root, the leader
  asks the replicas for their rows (`PeerMessage::AnchorRow`), and sends
  its anchor, the evidence that ends the space, only once a quorum of the
  group holds its root and no replica another. A replica holding another
  is an alert ("divergent replicas"), nothing sent.
- `Unlisted`: the leader hands its leadership to a replica whose node key
  the client's listing holds (`Local::Transfer`, Raft's
  `transfer_leadership`), at most once a window of the space's clock; with
  none listed it alerts and waits.
- The queue only resends the same bytes until the venue answers
  (`Fate::{Done, Again}`); the client keeps the answer and answers the
  leader's next offer from its reads. `VenueClient::unsettled`, the
  queue's held-back windows, `recheck`, `push_listed`, the leader's
  `signed`/`foreign`/`seeded`/`refused` bookkeeping, `take_up` and
  `seed_waiting` go.
- The three reads pin D′ keeps (status, `AnchorKeys`, `Last`/`Anchors[w]`
  through the new `VenueClient::held`) answer from a cache the client
  fills on its own thread: Kreivo's reader reads the windows the leader
  asks of; jam-dev's client gained a reader thread (it read on the batch
  thread before). A client sends nothing over another root unless the
  leader offered it after reading that root.
- The leader's alerts are kept for operators and tests
  (`Node::anchor_alerts`).

**Folded:** slice 6's L5 (jam-dev's `push` wedge: no push refuses a signer
now) and the untested once-a-window recheck, both gone with the hand-back.

**The doc pass:** `spaces-pallet.md` §9 (the 7.1 review's L6: the five
outcomes and the client's table, no hand-back, the reads), §1's
authorities; `proving.md` §7; `docs/operations.md` (new: the node key as
the anchor key, replacing a node, a restored backup or a cloned store as a
compromised key, the alerts, an ended space's re-founding).

**Tests:** the cluster's `anchoring` suite (13): anchors in order across a
leader change; a deposed leader stopped before its close and a successor
whose clock lags both offering window 0, one root, no evidence; the
divergence guard (a replica's row forged: no evidence, the alert); an
equivocation ending the space (the replicas agreeing: the evidence goes,
`Ended`); an unlisted leader handing off to a listed replica, which
anchors; one handoff a window (the listed replica down: one handoff, then
a wait; back, the next window hands off again); no replica listed (alert,
wait, anchored once listed); a delisted node refused the representative
and replaced; a non-founding node representing once registered; a long
wait across a failover; an aged window settled unsent; windows refused
unregistered. Every venue code through each client's table (the model's,
Kreivo's, JAM's). The cuts checker also checks the replicas' anchor rows
agree and every anchor is its row.

**The leader's anchoring, against `simplify.md` §4:** its state is four
fields (the last window settled, the last pass, the last alert, the last
handoff's window), from nine; its waits are one recheck (2 s), which a
pass reaches five ways (an unread root, not yet, unlisted, stopped, an
unsure guard), from sixteen wait, retry or settle paths. The plan's
"about two" fields was low (below).

**Lines** (`git diff --numstat 62981f95`):

| crate | added | removed |
|---|---|---|
| vos-node (src) | +451 | −680 |
| vos-node (tests) | +805 | −814 |
| vos-venue (src) | +505 | −694 |
| vos-venue (tests) | +173 | −133 |
| vos-jam-dev | +412 | −129 |
| vos-node-prover (src) | +32 | −71 |
| vos-node-prover (tests) | +13 | −41 |
| vos-cli (src) | +1 | −30 |
| vos-cli (tests) | +0 | −33 |
| vos-wire (src) | +42 | −2 |
| vos-wire (tests) | +15 | −0 |
| vos-checker | +5 | −5 |
| vos-pvm-proof (tests) | +10 | −14 |
| docs | +138 | −32 |

The leader's anchoring is 355 lines (the guard, the handoff and the
alerts among them), from 409 plus `anchor_keys.rs`'s 176; the queue's code
181 lines, from 338.

**Unchanged:** the node's kernel program ids
(`the_program_ids_are_the_repositorys` passes). The agent image's bytes
change: any change to `vos-wire` changes its symbols' crate hash, and the
guard's two messages are `vos-wire`'s; nothing pins the image before 7.8b's
`blobs.lock`.

**Gates** [measured]:
- `just check` green.
- The checker loop, `EXACTLY_ONCE_SEED` 7201–7204 with `CUTS_FULL`, the
  three exactly-once tests and `cuts`: green, 137–201 s a seed at load
  21–25; 58–71 anchors a seed, one a window, every one the replicas' row,
  no evidence.
- `just e2e-chain` green on its fourth run, 1,059 s: the same verdicts as
  7.1's; latency 49.5 s at Kreivo and 72.3–120.2 s at JAM, each under its
  gate; Kreivo's sovereign charged 7.5 UNITS (5 anchors, 2 submits, one
  deposit forfeited; 7.1: 9 anchors, 11.5 UNITS: window 0, before the
  registration, is no longer sent again after its refusal); the audit
  clean over 565 carriers. The three runs before it failed:
  - the Kreivo client alerted window 0's `WindowNotAfterLast`, a window
    before the registration: fixed, that refusal is routine and quiet;
  - the representative's creation `Unconfirmed` at JAM: its client had not
    yet read the space on its own thread, so listed no key; the run now
    waits for the read, as it waits for Kreivo's;
  - a JAM package the node took without a work report within 90 s, at the
    audit, under a host load of about 24; not seen again.

**Where the plan was off:**
- **"The representative's close writes `anchor(w)` by apply":** the row is
  written by the commit that finishes the representative's cut build
  (where its close is made, `closing(w)`), not by the agent's apply of
  `Input::Close`: that input carries the root only when a path is sent,
  and writing it there changes the agent image. The cut is fixed by the
  committed log, so the row is the same bytes on every replica, which is
  what the guard compares (`plan3-fable.md` verified the closing row's
  determinism).
- **The divergence guard needs a quorum, not only "none differs":** a
  replica that has not built the cut answers no row, so "none differs"
  alone would send evidence on the leader's row unchecked.
- **"One handoff a window"** is per window of the space's clock, not per
  window anchored: keyed on the window anchored, a failed handoff (the
  target down) would never be retried.
- **`SubmitOutcome::Retry` carries its code:** the log, the e2e's checks
  (`Retry(5)`) and the worker's bound on a venue's failures to judge need
  it.
- **The leader's state is four fields, not about two;** the wait paths
  one, reached five ways.
- **Node-side lines:** vos-node's source fell by 229, not the 1,000–1,400
  `simplify.md` §4 counts for C1–C11 on the node: most of that is C9–C11's
  (7.3). jam-dev grew by 283 for its reader thread, which pin D′'s
  off-the-batch-thread reads ask of every client.
- **`docs/operations.md` did not exist** on vos-core; 7.2 starts it.
- **The venue `Status` keeps its four variants:** the leader no longer
  reads it but for the guard's skip of an ended space; the pin keeps the
  status read.

### The review's fixes

Fable's review (`research/slice-7/7.2-fable.md`: fix, then merge) and the
owner's answer to its M1 (S34, `owner-decisions.md`), folded as further
commits:
- **M1, S34: the majority decides.** A quorum of the replicas holding the
  leader's row sends the evidence over a dissenting minority; each
  dissenter is alerted by name with its root (`AnchorAlert::Divergent`;
  equal to the venue's held root it names the equivocator). Without a
  quorum nothing is sent and nothing settled, the guard asking again a
  recheck later; a dissent never settles a window. Tests: a compromised
  replica that anchored a forged root and answers it as its row does not
  block the evidence; with no quorum the guard waits, then sends once a
  quorum holds the row. Pin D′ amended.
- **M2:** the Kreivo client keeps, by signer, the code and the listing
  read when the venue refused it unlisted (7 `NotAuthority`, 11), answers
  it unlisted and sends nothing under that listing, and forgets it when a
  read finds another; a test through a transport refusing `NotAuthority`.
  `operations.md`: a Kreivo removal in one sitting, authority then key.
- **L1:** the pass runs once a cut is built or the recheck is due, not
  before every batch; the guard stops at a quorum, with a 200 ms grace to
  name the rest. **L2:** no later window is offered after the evidence.
  **L3:** `AnchorAlert::Evidence`; a stop alerted once a window. **L4:**
  with the venue's time unread nothing is judged aged. **L5:** the handoff
  damper is the node's, across leaderships; no handoff before the space's
  origin. **L6:** `may_represent` and `operations.md` say the
  representative is refused until the venue client has read the space.
  **L7:** pin D′'s "by apply" and "if any differs", and the runbook's
  bullets.
- **Info:** `AlreadyAnchored` caches the root held; the prover's retry
  wait stops doubling at the longest window; a `Never` by the venue's own
  refusal (the window before the registration) logs as a warning. The
  leader's alerts are raised once a leadership each; with that, its
  state is three fields (the last window settled, the last pass and the
  cuts built then, the alerts raised), the handoff damper now the node's.
- Not taken: a distinct `Unplaced::VenueUnread` (L6's alternative); the
  documentation covers it.

**Gates after the fixes** [measured]: `just check` green; the checker
loop, seeds 7205–7206 with `CUTS_FULL`, green (174 s and 121 s; 51 and 54
anchors, every one the replicas' row, no evidence); `just e2e-chain`
green first time, 1,670 s at a loaded host: the same verdicts, latency
125.7 s at Kreivo and 79.4–169.7 s at JAM, each under its gate; 5 Kreivo
anchors; the audit clean over 574 carriers.

## Step 7.14: masking the segment chips

Branch `s7/7.14`, from vos-core `61c0950e` (7.8a merged).

**Built:**
- **The finalize hook** (`003ae19a`): `BuiltInComponent::LOGUP`
  (`Logup::{Pairs, Single}`), the 14 chips that finalize unpaired declaring
  `Single`; `add_constraints` leaves its fractions unfinalized and the
  evaluation finalizes them as before, so format 35's constraints and
  proofs are unchanged. `Logup::batches(n, extra)` is the batching the
  masked evaluation takes: the chip's own, the blinding fraction joined to
  its last batch, so masking adds **no interaction column and no degree**
  to any chip (the blinding's denominator `combine_B(1)` is a constant).
- **The fixed chips padded** (same commit): the tables repeat their
  entries past them with no multiplicity, the boundaries, the program's
  code and the jump table add rows that claim nothing, when a floor asks
  for more rows; their preprocessed columns follow the given size. No
  production path passes a fixed chip a floor above its natural size.
- **`MaskedComponents` extended** (`cd532763`): `Active` (the active-chip
  mask, which `draw_relations` draws by; `()` for the wrap), `layout`
  (the set under any relations), `active`, `public_sums` (the components
  whose claimed sums the public values fix, which the prover leaves
  unblinded). The final verifier's `Claim` gains `bound_sums`, checked
  after the logup total. **A per-component `h`** (`masked::mask_rows`):
  twice the rows a column of the component reveals, `4|O| + q(|O| + 1)`
  for its widest offsets, rounded up, at most the format's; the mask
  layouts are keyed by size and `h`, R1 checks each class at its `h`. The
  wrap's draws, masks and bytes are unchanged (its `h` is the format's).
- **The masked segment** (same commit): `vos_pvm_proof::masked`
  (`SegmentComponents`, `MaskedChipEval`, `bound_sums`, `public_values`,
  `drive_masked_chip`; prover side `masked_segment_trace`), and
  `vos_pvm_recair::masked::segment` (`prove_segment`, `verify_segment`,
  `floors`; `prove_segment_forced` under `seeded-masks`). The public values
  after the main root are the boundary states, one M31 a byte; the four
  boundary chips' sums stay unblinded and are checked against them; the
  interaction trace takes a chip's blinding fraction on its running sum
  alone (`β·(1 − (r + 1)/N)` at coset row `r`). No format is admitted:
  the tests and the measurement name masked formats of their own.

**Gates** [measured]:
- **Degree audit** (`circuit`'s
  `the_masked_segment_chips_pass_the_degree_audit`): every chip's masked
  evaluation, 5,177 constraints, by degree `[0, 23, 4395, 759]`, R5's
  histogram exactly; the built set at its layout declares them, each
  bounded at `log_size + 2`.
- **Soundness** (`recair/tests/segment`, the small kernel: φ8..12 set, φ7
  summed and cleared, 17 chips): acceptance with every chip at `2^8`,
  `2^9` and `2^10` at least on Poseidon2-M31 and Blake2s, and (heavy) at
  the device floors, blowup 4 with 43 queries (`2^11`, 137 rows revealed
  of `h = 512`) and blowup 2 with 86 (`2^12`, 266 of 1,024); R1 over every
  column class (11) in one attempt; a broken constraint (the register
  ledger's `BothRealH`) at row 0, the last row (across the wrap) and mid-way
  refused by the prover and, forced, by `OodsNotMatching`; an unbalanced
  range table refused by the logup total, and with the CPU's blinding
  fraction moved to cancel it, refused by the prover and, forced, by
  `OodsNotMatching`; 34 tampers (each tree's samples and queried values,
  a salt, a blinded and a public claimed sum, the interaction PoW, the
  boundary states, the structure, the log sizes, the mask, the
  configuration, another circuit's root) refused, none a panic. The mask
  invariant and R1's refusal are the generic prover's tests, the lifting
  the wrap's (generic). Soundness 10 (both bit counts pinned) is a
  registered format's: 7.16 pins format 43's.
- **Leakage**: R1 on every class (above); witness indistinguishability and
  uniformity at 16 proofs a kernel in `check` (34,157 hypotheses, smallest
  p 2.3e-4 and 2.6e-6, none refused) and 64 under `heavy-gates`; the
  unmasked control (format 35) refused by the pooled KS; no hidden state
  (φ7's sum and its low half, both `memory_commitment`s) in a proof's
  bytes; no opening shared by two proofs of one run (34,156) nor two
  kernels' from one seed; a right guess reproduces every unmasked sum and
  only the boundary chips' masked ones, the totals equal; one shape for
  two kernels, by the kernels' construction (the same code length and
  steps), not a property of the prover (below). **A deviation** from slice
  6's pairs: a segment of the node's shape publishes its whole boundary, so
  under equal public values a run has no other witness; the two kernels
  differ in φ9 (as 6.6's real wrap differed in the program id). The gates
  of two witnesses under equal public values belong to the device shape
  (arguments through the witness input, the io-hash only): 7.15's.
- **What 7.14 does not hide or pin** (the review's M2, M3): the shape, the
  chips (`active`) and their log sizes (the run's, above the floors), is
  public and witness-dependent until pin J's device program id pins it and
  the prover pads to it (7.15; `prove_segment` takes no pinned shape
  today); the transcript does not mix `active` (as format 35's does not),
  which 7.15 closes by mixing the program id into the header and verifying
  against it; `bound_sums` and the public sums assume the four boundary
  chips, which the device shape (no memory roots, the io-hash in φ9..12)
  generalizes.
- **Format 35 byte for byte:** `fixtures::the_fixtures_are_the_generators`
  and `the_fixtures_are_judged` pass (`segment-35.*`, the wraps, `H_FOLD`
  and the program ids unchanged).
- **`just check`:** green at `9b5ff346` (each under a 12 GiB scope,
  `nice -n 10`, `CARGO_BUILD_JOBS=8`, another agent's runs on the machine,
  load 12–46). Its first full run failed `vos-node`'s `tree_crash` ("no
  round was killed between a build's batches", a kill-timing test under
  load); its rest (the agent's crates and `test-reads`) rerun green, the
  crash test cutting 4 of 12 rounds mid-build.
- **`just test-proof`** (the leakage gates at their medium N, 64 proofs a
  kernel on the masked segment): green, 568 passed in 48 suites, about 45
  minutes; the segment's six heavy and leakage tests 401 s; `constants::`
  with every pinned value unchanged; the carrier audit clean (451
  `WrapRandomness` needles). Its first run failed
  `window_kernel::the_window_is_stated_at_the_model_venue` from before this
  step: since 7.2 (`4f9babad`) a venue answers a repeat as accepted
  (`SubmitOutcome::judged`), and the test still expected code 6; it now
  expects `SubmitOutcome::Accepted` (`6d0b50c9`).

**Commits:** `003ae19a` the finalize hook and the floors; `cd532763` the
trait's extensions, the per-component `h` and the masked segment;
`8eb0da9e` the gates; `3d1c08a0`, `bd7edfad` the spike's `real` cells and
their runs (the latter also carries `proving.md` §5 and §8); `2a378382`,
`9b5ff346` a doc link and clippy; `6d0b50c9` the window kernel's repeat;
this record.

**Masked against unmasked, x86** [measured, `spikes/s7-device/runs/x86-real.jsonl`;
the auth statement, 19,192 steps; the Blake2s channel; 4 threads pinned to
four P-cores, median of 5; load 8.5 falling to 5.2, another agent's runs
on the machine; `real` is the masked segment prover, each chip padded to
four times its `h`, the OS's masks]:

| cell | plain | masked | ×time | plain peak | masked peak | ×mem | plain bytes | masked bytes | ×bytes |
|---|---|---|---|---|---|---|---|---|---|
| built, 2:43:20 (h 512) | 3.28 s | 6.72 s | ×2.05 | 3,486 MiB | 7,949 MiB | ×2.28 | 1,893,890 | 2,123,121 | ×1.12 |
| floor, 2:43:20 (h 512) | 0.85 s | 2.23 s | ×2.62 | 1,251 MiB | 2,958 MiB | ×2.36 | 1,217,153 | 1,419,714 | ×1.17 |
| lean, 2:43:20 (h 512) | 0.68 s | 1.78 s | ×2.63 | 968 MiB | 2,279 MiB | ×2.35 | 536,273 | 679,897 | ×1.27 |
| floor, 1:86:20 (h 1,024) | 0.70 s | 1.78 s | ×2.53 | 812 MiB | 2,002 MiB | ×2.47 | 2,245,957 | 2,620,870 | ×1.17 |
| lean, 1:86:20 (h 1,024) | 0.50 s | 1.34 s | ×2.66 | 652 MiB | 1,565 MiB | ×2.40 | 948,004 | 1,228,742 | ×1.30 |

- The built masked proof verifies in 29.8 ms (plain 26.5); R1 one
  attempt, 18–24 ms at 43 queries (137 rows), 71–73 ms at 86 (266).
- **Against 7.0a's proxy** (same cells, 4 threads): the real masking
  costs ×1.34–1.51 the proxy on floor and lean (1:86 floor 1.33 → 1.78,
  lean 0.89 → 1.34; 2:43 lean 1.18 → 1.78), ×1.25 on built; so the
  masking factor on the segment chips is **×2.5–2.7** (×2.05 built), at
  the wrap's ×2.6–2.9, and the outlook's "masking beyond the proxy ×1.0–1.4"
  is at or past its top.
- **Memory ×2.3–2.5**, above the proxy's ×1.9–2.0: the masked prover keeps
  each chip's trace for the interaction (a chip's interaction generator
  consumes its trace, and R1 may retry) beside the interpolated main
  columns. A lever for 7.17: the interaction from the trace once, or a
  borrowed trace.
- **Bytes:** the masked lean shape fits pin J's 1.5 MiB at blowup 2 with
  86 queries (1.23 MB, the Poseidon2 chip not counted) and at blowup 4
  (0.68 MB); the masked floor fits only at blowup 4 (1.42 MB).

**Where the plan was off:**
- **No chip is at half the floor:** every segment chip's running sum reads
  its previous row, so each has a two-offset column and takes the full
  `h`. The per-component `h` is built (and generic), but on the segment AIR
  it is uniform; pin J's "`|O| = 1` components at half the floor" and
  `proving.md` §8's sentence (amended) hold for no segment chip.
- **The 14 unpaired chips need no special treatment** beyond the
  finalize hook: joined to the last batch, the blinding adds no column to
  any chip, paired or not, and no degree.
- **The fixed tables pad without an AIR change**, by repeating their
  entries (every padded row a valid entry, so a multiplicity there claims
  nothing false).
- **Witness indistinguishability on a segment** needs a deviation (above);
  the device shape (no memory root out, arguments through the witness
  input) is where equal public values admit two witnesses: 7.15's gates.
- **The masking factor** is ×2.5–2.7 under load, not the ×1.8–2.1 proxy
  floor, and peak memory ×2.3–2.5; re-measured quiet after the review's
  fold, ×2.14–2.19 and ×2.1–2.2 (below): M5's outlook's masked rows sit
  past its ×1.0–1.4 "beyond the proxy" only by load.

### The review's fixes

Fable's review (`research/slice-7/7.14-fable.md`: fix-then-merge, no
soundness or zero-knowledge defect), folded:
- **M1** (`a14152f3`): `verify_segment` takes the preprocessed root,
  mandatory; `circuit_root` computes it from the program and the shape.
  Gates (`the_circuit_root_pins_the_tables_and_the_code`): the honest root
  every proof's (two seeds), each verified against it; another program's
  root refuses them as `Circuit`; a prover-chosen table (the power-of-two
  table's entry on a padding row of no multiplicity made `(70, ·)`, every
  constraint held, the logup balanced) verifies against the root it
  commits and is refused against the program's.
- **M2, M3:** the module docs (`vos_pvm_proof::masked`,
  `vos_pvm_recair::masked::segment`) and the qualifications above.
- **L1:** the window kernel's doc; the repeat is shown held once
  (`ModelVenue::statements_held` 1 after it).
- **L2:** the forging seam (`MaskedSegmentTrace::{main,preprocessed}_columns_mut`)
  under `vos-pvm-proof`'s `seeded-masks`, which `vos-pvm-recair`'s
  enables; `check-no-leaks` forbids the feature by name.
- **L3:** a forced proof blinding the boundary chips' sums too (the
  blinding summing to zero, every constraint held) refused by the boundary
  binding (`Logup`); a log size smaller refused.
- **L4:** `Logup::batches` asserts a chip has a fraction; `blinded` refuses
  a chip with no running sum (every segment chip has one, the census
  below).

**The overhead (the review's option 1)** (`a14152f3`, `9db9f0b3`),
behaviour-preserving: the seeded wraps and the fixtures byte for byte
(`fixtures::`, `constants::`), the seeded masked segment's draws in the same
order. Profiled first (perf and stage timings, the floor at 2:43:20 on a
quiet machine, 1.73 s): the Merkle trees' Blake2s 30% (every column lifted
to the composition's height, `+2` levels over the trace, against `+1`
unmasked), the composition 23–27%, `prove_values` 13–15%, the interaction
17%; the masking's own steps small (layouts 40 ms, the digest about 20 ms,
the masks' scatter 16 + 8 ms, R1 13–20 ms, the set's three builds 4 ms each).
- each chip's interaction trace generated from a borrowed trace (the
  unmasked prover's too, its traces still dropped as each is consumed);
- the masked prover's main columns borrowed (`MainColumns`): each component
  interpolated, masked and its coefficients dropped in turn, no copy of the
  trace and no unmasked coefficients kept across attempts (a retry, rare,
  interpolates again);
- the mask layouts cached by `(size, h)` for the process (the class's lift
  and offsets do not enter a layout);
- a masked chip's batching computed once, not every evaluation;
- R1's elimination sixteen columns a SIMD word (`rank_m31`).
Not taken: the set built once per prove (3 builds, 4 ms each); the
masks' scatter (16 ms over every main column); **the witness digest in
BLAKE3** (about 20 ms, 1%): it seeds the masks, so it moves every seeded
masked wrap (`wrap*.proof`, `statements.cases`, the conformance vectors),
a re-pin this step must not make; it fits 7.21's re-pin, `proving.md`'s R4
note unchanged until then.

**Masked against unmasked, x86, re-measured** [measured; quiet, load 1–2.5;
4 threads pinned to four P-cores, median of 5; `runs/x86-real-folded.jsonl`
after, `runs/x86-real-quiet.jsonl` the masked prover before the fold on the
same quiet machine]:

| cell | plain | masked before | masked after | ×time | plain peak | masked before | masked after | ×mem | masked bytes |
|---|---|---|---|---|---|---|---|---|---|
| built, 2:43:20 | 2.24 s | 5.48 s | 5.49 s | ×2.45 | 3,567 MiB | 8,066 MiB | 7,513 MiB | ×2.11 | 2,123,906 |
| floor, 2:43:20 | 0.80 s | 1.86 s | 1.71 s | ×2.15 | 1,249 MiB | 2,919 MiB | 2,749 MiB | ×2.20 | 1,416,741 |
| lean, 2:43:20 | 0.60 s | 1.43 s | 1.29 s | ×2.14 | 976 MiB | 2,352 MiB | 2,153 MiB | ×2.21 | 687,456 |
| floor, 1:86:20 | 0.62 s | 1.46 s | 1.36 s | ×2.19 | 817 MiB | 1,978 MiB | 1,759 MiB | ×2.15 | 2,610,521 |
| lean, 1:86:20 | 0.48 s | 1.07 s | 1.02 s | ×2.14 | 641 MiB | 1,516 MiB | 1,402 MiB | ×2.19 | 1,219,144 |

- The fold took 5–10% of the masked time on floor and lean (none on built,
  within noise) and 6–11% of peak memory; R1 16, 14, 12, 49 and 35 ms
  (from 20, 17, 18, 67 and 58).
- **The masking factor, quiet, is ×2.14–2.19 on floor and lean** (×2.45
  built); the first table's ×2.5–2.7 was the load's (load 5–8 then). Memory
  ×2.1–2.2: the masked columns' coefficients at `2N` and their extension,
  not a copy the prover keeps.
- What remains is the masking's arithmetic as built: every column at `2N`,
  the composition at `4N` and every tree lifted one level more than
  unmasked.

**The cubic census (the review's option 4)** [measured,
`circuit`'s `the_masked_segments_cubic_census`, `9db9f0b3`]: of the masked
segment's 759 cubic constraints, **723 are the paired logup's batches** and
**36 are gates** (the CPU's 34, the memory ledger's 2); the 4,377 quadratic
gates and 18 quadratic batches the rest. Every fraction batched alone
(`Logup::Single`, the blinding still joined to the last) is quadratic, at
**1,464 interaction QM31 columns against 741** (×1.98, 2,892 base columns
more). So **a masked-only `Single` batching does not make the masked AIR
quadratic**: the 36 cubic gates keep the composition at `4N`
(`MASKED_LOG_CONSTRAINT_EXPANSION` 2) unless they are rewritten, an AIR
change for the segment's chips (the CPU's degree-3 gates, the memory
ledger's two). With them rewritten [est]: the composition and every tree's
lifted height one level down, about the 30% Merkle and 25% composition
shares halved, against the interaction columns doubled (the interaction
17% of the time, the CPU's columns most): net about −20–30% of the masked
time, toward ×1.6–1.8; not measured.

**Gates after the fold** [measured]: `just check` green at `b5252bf9`
(1,441 passed in 111 suites, the segment's 13 tests among them);
`just test-proof` green, 568 passed in 48 suites, 37 minutes, the segment's
heavy and leakage tests 251 s (64 proofs a kernel), `constants::` and the
carrier audit (451 `WrapRandomness` needles) clean; `fixtures::` byte for
byte (format 35, the seeded masked wraps, `H_FOLD`, the program ids).

**Options 2 and 3, recorded for 7.16** (security parameters, not applied):
a tighter `h` (`2·revealed` rounded up, without the second ×2: `h` 512 → 256
at 43 queries, 1,024 → 512 at 86, floors `2^10` and `2^11`), its retry rate
measured; the floor at `2h` rows, not `4h` (a cubic constraint over columns
of degree below `N + h` has a quotient of degree `2N + 3h ≤ 3.5N < 4N` for
`h ≤ N/2`), with the degree audit and the lifting test re-run. On this
statement the pads are about 4% of the cells, so each yields a few percent
here, more on lean kernels; R1 halves with `h`.


## Step 7.7: the design round

Pins G, I, K and L checked against the code at vos-core `4e7b4982` and
the owner's S21–S25, S7, S28 and S29, with the Fable review's H1, H2, M3,
M5, M7 and M8; written into `proving.md` §8 (the hash, the tree, the
statements, format 42, the PRF derivation, the device library's API) and
`identity-and-authority.md` §5 (the origins, credentialed calls, the
binding, the guards, ingress's checks with every refusal code, the apply
rule), §6 (the credential actor: its rows, its ring, its methods,
re-founding) and §7 (the in-space credential and its threat model). The
plan's pins now summarize those sections and point to them.

**What the code holds today** (the pins' starting point):
- the logged caller is `vos_wire::ids::Principal`, `Client` 0, `Agent` 1,
  `Instance` 2; no origin of the identity design's ABI was reserved, and
  the batch's `Input` has no session-less kind (indexes 0–9 taken);
- ingress's refusals are `Rejection` (indexes 0–8), mapped to HTTP statuses
  in `node/host/src/ingress.rs`; the HTTP layer picks a body's limit by
  path before decoding (`/install` alone is larger);
- `GET /` answers the node's key, which clients pin; no route answers the
  node's time;
- an agent's state holds its `SpaceId` (`keys::space`), `SpaceId::NONE`
  without a genesis; an `AgentId` is unique in its space (the creating
  node's number in its top byte), not across spaces;
- refine checks a method's role in `refine/invocation.rs`, from the
  schema's `MethodSchema::role`; `MethodSchema` has no credential field;
- `vos-pvm-poseidon2`'s `compress` is the width-16 permutation of
  `left ‖ right`, truncated to 8 words; formats 30 and 37 are registered,
  reserved, at unmasked counts; 41–44 are free.

**Fixed in the pins** (each an inconsistency or a gap):
- **The tree's leaf no longer hashes its slot:** a `u32` slot does not
  fit one M31 word, and 32 direction bits recomposed mod p would alias; in
  a positional tree the path places the leaf. `leaf = C(T(leaf), member)`.
  A write is 33 calls of `0x402`, not 32 (the leaf and 32 levels).
- **Every hash pinned as `C(l, r)`,** the compression of two 8-word halves,
  with tags as `[t, 0, …, 0]` blocks and 32-byte digests mapped to words by
  `W` (eight 31-bit words): the plan's `P2(TAG ‖ s ‖ scope)` had 17 words
  for a 16-word permutation. The nullifier is `C(C(T(nf), s), scope)`.
- **The ring's freshness runs from a root's supersession,** not from its
  write: as written, a root current for a month became stale the moment an
  unrelated enrollment replaced it, so every honest path fetched before
  that change failed at once. Revocation still binds within
  `ROOT_MAX_AGE` of the revoking batch (H2's goal). The ring is also
  checked at apply, by batch time, not only at ingress, which the plan's
  7.11 test already assumed ("by batch time").
- **A route of its own,** `POST /agents/{id}/credentialed`: the HTTP layer
  caps a body by path before decoding, so a 1.5 MiB body cannot share
  `/calls`' 68 KiB limit; and `GET /time` for the node's clock, since
  `GET /` serves the pinned node key.
- **S29's alternative is format 44,** not 42 with other parameters: a
  number names one set of parameters.
- **A space without a genesis refuses credentialed calls** (`NoSpace`):
  every such space's scopes would collide under `SpaceId::NONE`.
- **The scope's BLAKE2b preimage takes a domain tag,**
  `"vos/cred/scope/v1"`, as the binding's does.
- **The program id for format 42 is the circuit's,** chosen by `kind`,
  never by the schema; the schema names a device kernel only for format
  43, in the guard's `device` field, which exists from 7.11 so that M5
  moves no pinned blob after 7.8b's `blobs.lock`.
- **"Once in this scope" is the handler's rule:** a login's nullifier is a
  stable pseudonym; a handler that admits a member once keeps its own set.
  The identity design's wording ("once in this scope" on the origin) is
  corrected.
- **`path` is an ordinary query,** under the query route's limits: the
  host has no per-method limiter, and the tree's shape is not secret from
  its readers. Queries are signed, so the library signs each `path` with a
  key drawn for it alone.
- **The agent finds its credential actor** through a system row its
  install writes (`credentials → instance`, one an agent); an `Auth` guard
  without one fails install (`Failure::Credentials`).
- **`proving.md` §8's stale text** (a balance row and range check for
  payment, a binding to a challenge, a Poseidon2 root kind for credential
  maps) replaced by the decided statements; §4's table and §12's decision
  4 follow; 30 and 37 retire when 42 and 43 register.
- **7.11's tests and gate:** the 1.4 MiB device body passes the route's
  size and is refused `Format` until 7.20 admits 43; the 1,000-a-second
  gate is 10 cores of verifying at 10 ms (Q6).

**The owner's questions,** with options and recommendations, in the
plan's "Open questions": Q1, revocation does not stop payment (recommended:
the ledger's `rekey` and `freeze` under an operator role); Q2, path fetches
link a pseudonym to its member for operators (recommended: the library
refreshes paths apart from proofs; a bucket query later); Q3, a duplicate
answered `Replayed` without its outcome (recommended: as pinned); Q4, the
PRF output as a Java string (recommended: accept, and P1 checks Play
services' FIDO2 client for a `byte[]`); Q5, "once in this scope" in the
handler (recommended: as pinned); Q6, 7.11's rate gate on a host of at
least 12 executor threads (recommended: keep, threads recorded).

**Answered** (2026-10-26): the owner's S37–S44 folded into the pins, the
design docs and the plan (`owner-decisions.md`): S37 Q1, S38 Q2, S39 Q3,
S42 Q4 (no passkeys: the Keystore and a security key), S43 Q5 (a `once`
guard, superseding "the handler's rule" above), S44 Q6; with S40 (the
demo in s4) and S41 (the node's binary API and a gateway, step 7.10b).

**Left to the steps:** `SECURITY.md`'s entries (the path leak, the handle
copy, the containment) with 7.11 and 7.12, as the plan has them.

**Review (Fable):** fix-then-merge; M1–M8, L1–L13 folded; owner S46–S51
(`research/slice-7/7.7-fable.md`, `owner-decisions.md`). The fixes: the
`once` row written only when the handler returns `Ok`, `b` recorded
whatever it does, and 7.11's test (M1, S47); the demo client's paths and
time over a `vos-api` SSH subsystem on the gateway, under a fresh key,
and the s4 app's client key sending the claims of keyless members (M2,
S49); the facility's own chrome form for the payee and the amount, the
server's request a prefill, the method and its `once` guard named
before a sign-in, the grant and a call's confirmation two prompts (M3,
S48, L5); the demo's ledger, rows by name with `invite_row`/`claim_row`,
`mint`, `transfer`, `balance`, `rekey` and `freeze` (M4); `path_query`
addressed by the agent's id and signed over its identity, and
`root_query`/`root_answer` and `time_request` added (M5); 7.10b's
dependency 7.7, beside 7.9 and 7.10, the node's HTTP deleted after 7.6's
final run or T1 re-measured, the chain 9.5–13 weeks of steps (M6, S50);
the input's tag `"vos/device/input/v1"` (M7, S51); the scope an input
of the nullifier's compression, neither preimage hashed in the circuit
(M8). The lows: a security key always with user verification, one
credential under the pinned `rpId` `"vos.device"` (L1); which enum's
`Replayed` and `Once` (L2); `Time`'s bound stated (L3); the operator
console signs in the operator's client (L4, S46: operator requests
signed, socket-only until built); the client's per-connection key, no
token, no remembered grant (L6); `Threads::Auto` an even split until
7.17, the facility unsupported below API 30 (L7); the joint circuit a
floor, the in-space ledger custodial by design (L8); 7.10b's frame
grammar, frame error and kind table first (L9); `CredentialRefusal`'s
codes renumbered in check order, `Once` 9, `RootUnknown` 10,
`RootStale` 11, `Proof` 12 (L10); agents and methods pinned at
enrollment (L11); `node/SECURITY.md` and `vos-device`'s `SECURITY.md`
named (L12); the arguments in clear and the online set at each tree
change in §7's residues (L13).

**Gate** [measured]: `just check` green at `d524aef3` (1,441 passed in 105
suites). Its first run failed `anchoring::a_dissenting_replica_does_not_block_the_evidence`,
a race in the test as 7.2 left it, 2 runs in 5 on `4e7b4982`: the venue
ends the space inside the leader's offer, and the test read the leader's
alerts before the offer's answer raised `Evidence`. The test now waits for
the alert (`d524aef3`); 8 runs in 8 passed.

## Step 7.5: the load model and its drivers

From vos-core `e5389045`, in two commits and this entry.

**S35, recorded** (`owner-decisions.md`): one machine besides the
desktop, `compumax`, holds the runs' three nodes, each its own unit, cap,
cores and data directory; the drivers and the coordinator run on the
desktop. §7.6 and the targets now say so: run 2's knee is one host's, not
T2's; T2 and the rerun without the slowest host are recorded as not
measurable until more machines exist. S35 does not name T5: run 5 kills
one of compumax's nodes, not a host, and whether that stands for T5 is
left to the owner (§7.6, the T5 row). `check` already admitted this
layout; a test now pins it (three nodes on one machine with their caps
summed against its memory; the drivers and the coordinator on a machine
with no node), and nodes sharing a data disk need its free space each.
`inventory.example.toml` is that layout.

**Built:**
- **The shard actor** (`agent/test-actors/shard`): accounts in a
  `CommittedMap` (an absent one holds `2^40`), `transfer` here or by a
  `credit` message to the payee's shard, `balance`, the workflow `tally`,
  `holds_at_cut` (`attest_at_cut` over the payer's row), and the identity
  rows (`fill_identities`, a thousand a call; `set_identity`). A testkit
  test covers it.
- **`agents`:** `K` shards and `I` idle agents by weight, the shard actor
  in each; `--identity-rows U` creates the stand-in identity agent on every
  node and writes its rows from eight clients. `deploy` founds the space at
  an origin it records, so drivers know each window's close `B_w + D`.
- **The model** (`tools/scale/src/load.rs`): users are keys from the seed
  and index, accounts by hash onto the shards; offered load `U·a·r`
  (`--users`, `--active`, `--per-user` or `--rate`); Poisson arrivals; the
  mix (`--mix`, default 80% transfers, 15% queries, 4.5% workflows, 0.5%
  reads at a cut); the cross-shard share `x` (`--cross`, random payees'
  `1 − 1/K` by default); Zipf(1.0) by rejection-inversion, ranks spread over
  the users by a stride coprime to `U`. Drivers split the users by index
  and the rate evenly; the first writes the identity agent 10 times a
  second, from 16 writer keys in turn.
- **The drivers** (`engine.rs`, `drive-local`): a planning thread draws and
  signs each operation up to 500 ms ahead; one sending thread (a smol
  executor) sends it at its time, single attempts (`call_at`'s semantics:
  no retry, no redirect followed; a `NotLeader` updates the leader hint),
  over at most 512 kept connections a node (64 opened before the load),
  calls to the shard's leader (read from the nodes before the load) and
  queries to a follower. A user's calls go one at a time in its session,
  in order; one refused before it ran gives its sequence to the next, one
  of unknown fate starts a new session. Workflows are read until they end;
  a read at a cut is read once for its window, then again from its close
  and timed from it (`cut_read`, against T4's 10 s). Every 10 s a line a
  kind (sent, answered, refusals by name, rate, p50/p99/p99.9, the late
  sends, the calls queued behind their user's), a total a kind at the end,
  and the mix as sent against its target, the driver's CPU over the load
  (`load_cores`) and by thread. The report sets each kind apart, the model
  beside it, and "not modeled" as before.
- **The capacity probe** (`"probe": true` in a plan given to `drive-local`
  by hand): every request to a node that does not replicate its agent,
  answered `Elsewhere` at once, before any signature check. The driver does
  all its work and the nodes almost none.

**What the driver needed to reach the rate** [measured, this desktop]:
signing is the planning thread's whole cost (curve25519 about 55% of the
driver's samples), and three costs of the sending thread went:
- a timer a request (600,000 pending at 20,000 a second for a 30 s
  bound): now a reaper every second shuts a late request's socket. The
  sending thread's CPU fell by about a third and its periodic stalls went;
- naming a refusal by formatting the whole answer (`Elsewhere` prints its
  contacts): 21% of the samples in `memcpy` under `Debug`; now by variant;
- a 16 KiB read buffer on each request's future, copied at each spawn.
Sessions are now timed from their first call: users keyed before the load
and first called a minute later were refused `StaleSession`.

**The gate** [measured, this desktop: Core Ultra 7 155H, governor
`powersave` (EPP `balance_performance`), load average 5–12 from other
agents' builds through every run; the driver pinned to cpus 1–2, one
P-core's two threads; four nodes on the other cores]:
- **The nodes cannot commit 20,000 calls a second here.** At 5,000 a
  second (K = 64, `x` = 98%) they fell behind (p50 12 s; refine and dry
  runs queued ~100 ms for executors each busy about 0.79 of a core, on a
  starved host: 92% busy, a third of it other agents' niced builds, its
  cores at 17% of their top clock, 0.6–0.9 GHz; the figures over the load
  alone, per the review's H1, where the first report's window took in the
  drain and showed the executors 28% busy); at 20,000 offered they answered about 10,000
  and lost leaders (92 elections), and the driver, its users' calls
  queueing behind unanswered ones, fell 60 s behind
  (`20261025T172227Z-s75-20k-a`, `…182820Z-s75-20k-b`).
- **The driver at 20,000 a second, by the probe** (60 s, `U = 4·10^5`,
  `a` = 5%, `r` = 1, K = 64, the default mix; three runs of the final
  binary, their records kept out of the repository): 1,199,155 sent and
  answered, 20,009 a second offered; **the mix within 0.06 points** of its
  target (worst: queries, 14.94% against 15%; transfers 80.04%, workflows
  4.51%, reads at a cut 0.50%, the cross share 98.44% against 98.44%); **0.62 and 0.77
  cores** of the pair over the load, the sending thread 0.22–0.26 and
  the planner the rest; 1.0% and 0.9% of sends more than 10 ms late, at
  worst 47–60 ms, all in the one or two intervals where the answers
  stalled about a second (answer p99 1 s, from 64 µs otherwise), none in
  the others. A third run, during another agent's burst (load 10, the
  cores at 0.4 GHz), went 1.32 cores and 16% late. Earlier runs before the
  last fixes: 0.80–1.21 cores, 0.7–1.8% late.
- **The full stack at a rate the nodes keep** (3,000 a second, 120 s,
  the same model, `20261025T192411Z-s75-full-3k-b`): 359,964 answered, no
  error, p50 164 ms, p99 655 ms; 0.01% of sends late; 0.27 cores; the
  mix within 0.05 points; every read at a cut served, 1.8 s past its
  window's close at most; the identity agent written 10 a second.
- **Verdict:** the driver sustains 20,000 calls a second on one core
  pair, its mix within 0.06 points, at about two thirds of the pair's
  CPU, against the nodes' cheapest answer; its schedule held within the
  M1 bound (1% of sends more than 10 ms late) in two runs of three, at it
  in one, the misses at node-side stalls. What the probe leaves out: the
  nodes' commits, and the reads of workflows and cuts (5% of operations,
  a signature and a request each more). It was not shown end to end:
  the localhost nodes commit about 5,000 a second here.

**Gates:** `just check` green (110 suites), on the first commit and again
on the last.

**Left for 7.6:**
- compumax reachable by ssh with the owner's key touched once
  (`ControlMaster`, README), lingering on, three directories of the
  harness's own on its data disk, its LAN address and its cores split in
  three; the desktop's wired address for the driver's entry
  (`inventory.example.toml`).
- Both machines on the `performance` governor, and the desktop quiet: at
  `powersave` under other agents' load the driver's cores ran at 0.4–2 GHz,
  and its cost per call varied threefold with them.
- The node's throughput is the first thing the runs will meet: at 5,000
  a second (T1's rate) four nodes on this starved desktop fell behind,
  their executors saturated. The review's node findings (below) name why
  T1's p99 is out of reach as built; the levers are scheduled after 7.6's
  first real run.

**What the plan left open, and how it was read:**
- "A share `a` active, each at `r`" and "users drawn Zipf(1.0)" cannot
  both hold per call: Zipf per call gives the hottest of 10^5 users 8% of
  all calls, a rate no session serves one call at a time. The model draws
  *who becomes active* Zipf and keeps `r` per active user, with a mean
  active span (`--active-s`, 300 s) the plan does not give.
- The mix's shares are not in the plan; the defaults above are the
  harness's, every report states them.
- "Within 1% of its target" is read as each share within one percentage
  point; every run's worst was 0.06.
- One core pair is read as two logical CPUs, here one physical core's two
  threads: the strictest reading on this desktop.

### The review's fixes

The Opus review said fix, then merge. Folded as further commits; the
owner's S36 recorded.

**S36:** with all three nodes on compumax, T5 kills one node's unit under
load: T5-partial, the host kill re-run when more machines exist
(`owner-decisions.md`, §7.6's run 5, the T5 row).

**High:**
- **H1, the report's window:** each driver's total now carries its load's
  span, first send to last (`load_from_ms`, `load_to_ms`), and the report's
  window is that span past the ramp: the drain, when the last answers and
  the reads at a cut come in, is left out. A test pins it. The 5,000-a-
  second run re-reported over its load alone changed the account above:
  the executors were saturated on a starved host, not 28% busy.
- **H2, routes:** a call goes to its agent's leader as last learned and a
  query to a follower up; a node that gives no answer, `Unavailable` or a
  `NotLeader` naming no leader is left out for 2 s and the leader's place
  moves to the next replica up; workflow and cut reads follow the same
  routes. Tests: the routes (a dead leader, a dead follower, the backoff's
  end) and the pool against a closed port (fails at once, holds no place).
- **H3, timing:** an operation is timed from its schedule, or from its
  send when it went early (`min`, not `max`, which had timed a late send
  from its send and hidden the lateness).

**Medium:**
- **M1:** every interval and total line counts the requests that waited
  for a connection (with the wait's p99) and the most in use at once; the
  report warns when the pool bound. The cap is `[harness]
  driver_connections` (512), and `drive` refuses when the drivers' caps
  together pass the nodes' `ingress_connections`. Several drivers on one
  machine (each its own entry, directory and cores) work, with a test.
- **M2:** the probe refuses to run when an agent is on every node, and
  writes no identity rows. The signatures the sending thread makes (calls
  signed again for their turn, the reads of workflows and cuts) are
  counted by kind (`signed_sending`): in the verification run, one per
  workflow, about six per read at a cut, one transfer in 2,000.
- **M3:** `--readers`, a share of all the agents (the shards and the idle
  ones) each reading once at a cut a window at a uniform time within it
  (`reader`, `reader_read`), the idle agents' identities read at the start
  sixteen at a time; a test of the windows. Reads at a cut wait a jitter of
  up to 0.5 s after the close, then read every 0.5 s: their latency is
  resolved to about a second, not two.
- **M4:** each driver counts each shard's distinct users and the sessions
  opened at it, and the report gives the totals and the busiest shard's.
  The report, the README and this entry state the mix's defaults as the
  harness's own, pending the owner.

**Low:** L1, the last interval's rate over its real seconds; L2, `cpu_s` a
delta each interval and `load_cores` over the send span; L3, sessions
unused for 55 minutes dropped; L4, the sampler reads involuntary switches
and the report gives preemptions a second; L5, tests of the pool's
accounting (a cap of two, six requests: two opened, four waited) and of a
session's turns (`NeverRan`, `Renew`); L6, T6 judges RSS once the
accounts stop growing (§7.6, the T6 row); L7, timeouts on the wait for a
connection and on `connect`. The engine is now four modules (`engine/`:
the sending thread, the pool, the sessions, the counts).

**The node findings (Q3)**, recorded here and as a T1 risk in the plan:
- one FIFO executor queue takes all work: signature checks, refine and
  the dry run as two hops, accumulates, queries and root builds;
- the single `vos-node` runtime thread also reads the store synchronously
  each batch (81–85% of a core in the verification run below);
- a group has one batch in flight (commit p50 41–49 ms plus apply
  25–29 ms in these runs), so T1's 50 ms p99 is out of reach without
  pipelining.
The review's levers, in order, scheduled after 7.6's first real run: refine
and dry run in one executor job; a priority lane for the batch path; batch
signature verification; the per-batch reads off the runtime thread;
runtime threads sharded by group; batch pipelining. Added now: the node's
`root_build_queue` and `root_build` stages (a root build's batch waiting
for an executor, and its run), and the report gives them with the refine
and dry-run queues.

**The verification run** [measured, `20261025T231824Z-s75-verify`, this
desktop, load average 9–13]: four nodes (executors 3), K = 64, 100 idle
agents, the identity agent, `U = 4·10^5` at 2,000 calls a second, readers
5%, 180 s; node n4's unit stopped 30 s into the load.
- **H1:** the window is the load past its 10 s ramp (170 s), the drain's
  lines out.
- **H2:** n4's loss cost 67 queries refused at its port, 397 calls
  answered `NotLeader` while its groups re-elected, and 41 broken
  connections; the interval it fell in had p99 1.3 s, and the next ones
  were back to 0.26 s. Reads followed the routes after this run only
  (50 reads at a cut had gone to n4 and been refused).
- **H3:** 0.01% of sends past 10 ms, at worst 12.6 ms.
- 358,692 answered of 359,197; the mix within 0.09 points; 12 reads by the
  readers' share, all served, 3.1 s past their window's close at the
  median; 29,558 users and 29,590 sessions over the 64 shards, 515 at the
  busiest.
- From about 100 s the three nodes left fell behind (their runtime
  threads 81–85% of a core, preemptions 1,700–2,600 a second from the
  host's other work), the pool bound (512 in use) and p99 rose to 16 s:
  the warning fired as it should.

**Two failures `just check` met on the loaded host (load average up to
34), both fixed:** `tree_crash` saw no round killed between a build's
batches (its kills land at random; it now runs up to three sets of twelve
rounds until one does); and anchoring's dissent test read the leader's
alerts the moment the space ended, while the leader raises the evidence
alert just after the venue takes it (it now waits for the alert). Neither
was this step's change.

**Gates after the fixes:** `just check` green (110 suites); `vos-scale`'s
42 tests.

## Step 7.3: reads, reports and the worker's edges

C9, C10 and C11 (pin D′), the prover worker's carried edges (slice 6's
M3, M4, L6 (a)–(f)) and item 68 (S30), from vos-core `61c0950e`, in
seven commits.

**No re-cuts (C9):** a read is served at the cut of the window it was
asked in, once the representative's `Closed` of that window applies, or
ends `NotClosed` at `B_{w+2}`; the caller asks again. `keys::moved`,
`RECUTS` and the chain of serving windows (`serving_windows` in
`vos-wire`, the node's `serving_windows`/`served_at`, refine's and the
testkit's walk) go; `READ_WINDOWS` and `CUT_KEEP` fall to 2; a request has
one cut proof.

**Cuts and reports only where a read waits (C10):** apply records a cut
only for the window of the agent's batch-time mark when a read waits on
it (`keys::reading`, written by the ask, and at the representative by a
stored report), or for every window crossed when the agent reports every
window (`Admin::ReportEveryWindow`, `keys::every_window`,
`Node::report_every_window`: the issuers' opt-in). What it waits on is
read before the result's steps, so a read or report a result makes never
cuts a window that result crosses. The leader's marker follows the same
rule, so an idle agent no read waits on gets none. Every report asks for
its path: `AgentRoot`'s and `Input::Report`'s `pending` go, and the
representative's `asked` table indexes every report. The prune of cut and
close rows runs from the latest recording's windows (`keys::cut_mark`, its
first and last, which replaces `serving`), a bounded range however sparse
the cuts; a `Closed` is taken only for a window the agent cut. The
representative needs no opt-in: its reports drive its cuts.

**No anchor for an unreported window (C11):** the representative's close
writes its closing and anchor rows only when some agent's row reaches its
cut.

**Item 68 (S30):** a row of a window's close that does not decode (the
report and close marks, a held `Closed`, the representative's last report
of a sender, its reading window) is moved aside under `keys::quarantined`
with its bytes, read as absent, and the step goes on; every replica's
apply logs it at error level. The representative's store of a report no
longer drops it silently on any such row.

**The worker's records are the agent's state (M3):** every replica's
apply keeps each attest at a cut as a node-local record
(`keys::attested(window, digest)`, the same bytes on every replica,
carried by snapshots), keeps it without its witness once the statement's
`Proven` applies (`Input::Proven` and `InputRef::Proven` name it), and
drops it once its window's roots age past `MaxRootAge`. The worker reads
its jobs from these records, from the earliest window a new one may still
come of, instead of the log: no watermark, no lost records, and a replica
that installs a snapshot and then leads holds every statement still to
prove, and every proved one still to submit.

**M4:** `prune` makes any aged unfinished job dead (its proof unheld)
and removes an aged finished one, whatever its agent's placement; each
unfinished job's kernel is held under `NODE_AGENT`, fetched from the
replicas when absent; a record whose kernel is absent waits for it, with
a warning, the step proving another job meanwhile (the review's M1).

**L6:** (a) compaction no longer waits on the prover: `PROVER_HOLD`, the
`proving` flag and the prover's mark go with the log scan (`NodeRow` 0x12
reserved); (b) the node marks its prover's table stopping before it waits
for a proof under way (`NodeRow::ProverStopping`), and an attempt ended
then is not counted against the statement; (c) a proof is written
`Proved` before it is pinned, so an opening re-holds it; (d) a venue's
failures to judge a statement are counted in its job (`Job::resubmits`),
across restarts; (e) a node that ends a proof no longer leading the agent
sends it to the leader (`PeerMessage::Proved`), which records it;
(f) `core-model.md` states the stall bound as the code measures it.

**Tests:** testkit: a read served at its own window alone; `NotClosed`
when the close misses it; only a window a read waits on is cut; a jump
past `MAX_CUTS` cutting nothing; the prune over sparse cuts; a `Closed` of
an uncut window refused; the representative's reading window; a row that
does not decode quarantined, the model agreeing; both hosts cutting every
window of an agent that reports every one (JAM's witness reading the
opt-in). Node: an idle agent appends no marker, a reading one one; an
agent misses the close, `NotClosed`; only a reported window anchored (two
idle windows nothing, an issuer's every window, a read's window); the
clock-jump cuts of an issuer; the cut model with the opt-in; a snapshot-
installed replica holding a queued statement's job and proving it once
after the leader stops (`a_snapshot_installed_replica_proves_a_queued_statement`,
M3); a record proved past compaction; a recorded statement's record kept
without its witness. Worker: jobs aging out, a rootless record refused;
a kernel held, and one fetched late proved; a stop mid-proof counted only when the node was not stopping;
resubmissions counted across restarts. The anchoring and Kreivo cluster
suites gain an issuer (C11 would leave their windows unanchored) and step
their clocks past each boundary before the close, so the reports land.

**Lines** (`git diff --numstat 61c0950e`):

| crate | added | removed |
|---|---|---|
| vos-node (src) | +381 | −350 |
| vos-node (tests, bench) | +433 | −163 |
| vos-node-prover (src) | +286 | −193 |
| vos-node-prover (tests) | +234 | −87 |
| vos-wire (src) | +201 | −103 |
| vos-wire (tests) | +21 | −17 |
| the default agent (refine) | +197 | −139 |
| vos-testkit (src) | +147 | −127 |
| vos-testkit (tests) | +204 | −136 |
| vos-pvm-proof (tests) | +6 | −3 |
| docs | +41 | −11 |

By commit, the sources (node, prover, wire, agent, testkit): C9 +103
−235; C10/C11 +256 −152; item 68 +260 −174; the worker +624 −380.

**Unchanged:** the kernel program ids (`the_program_ids_are_the_repositorys`
passes). The agent image changes (refine, apply and `vos-wire`).

**Gates** [measured]:
- `just check` green (its second run; the first failed `fmt-check` on
  `agent/default`, outside the workspace, fixed by `9ff16e89`).
- The checker loop, `EXACTLY_ONCE_SEED` 7311–7314 with `CUTS_FULL`, the
  three exactly-once tests and `cuts`: green, 114–190 s a seed at load
  14–21; 10, 20, 17 and 13 anchors, one a window, every one the replicas'
  row, no evidence; of 161–325 reads an agent, 10–27% ended `NotClosed`
  (the run's stops, partitions and clock jumps; none unserved).
- The cut's bench (`cargo bench -p vos-node --bench cuts`), against slice
  6's 5.06 µs and 373 ms, and beside vos-core `61c0950e` built apart, run
  alternately: at load 1.8–2.0, a write with a cut pending 5.34 and
  5.05 µs (base 5.21 and 5.15), a cut's build with 100 proofs 381 and
  369 ms (base 384 and 385): within 10%. Under the other agents' load
  (7–21) both builds spread 4.9–30 µs and 557–1,285 ms alike.
- `just e2e-chain` green first time, 1,227 s: the same verdicts; latency
  76.3 s at Kreivo and 61.6–121.7 s at JAM, each under its gate; one
  Kreivo anchor, 3.5 UNITS charged (7.2: 5 anchors, 7.5 UNITS): only the
  windows reads waited on are anchored; the audit clean over 443 carriers.

**Where the plan was off:**
- **C10's "the `asked` table goes":** the representative's roots map is
  keyed agent first, by the kernel's prologue (its key fixed with the
  kernel ids), so the close needs the per-window index the `asked` table
  is; it stays, every report an ask. The `pending` flag goes.
- **The opt-in is an admin command, not an `#[agent]` attribute:** an
  actor schema flag would change every actor's ELF and the kernel ids; the
  representative needs none (its reports drive its cuts).
- **The cut rule needs a replicated "a read waits" row:** apply reads
  points, not prefixes (JAM's witness), so `keys::reading` and
  `keys::every_window` are new rows, and the prune needs the last
  recording's window range (`cut_mark`) once cuts are sparse.
- **M3's marker holds the attest:** an "attested, unproven" marker alone
  would tell a new leader what it lacks, not give it the witness. The
  records keep the attest (its witness until proved), node-local but the
  same on every replica and in snapshots; they must outlive the proof to
  submit (a new leader holds a proved statement's record too), so they go
  with `MaxRootAge`, and a proved one keeps no witness. This replaces the
  worker's log scan, and with it L6 (a)'s compaction hold.
- **The node-side lines:** vos-node's source is +31 net, not the −1,000
  to −1,400 `simplify.md` §4 counts for C1–C11: C9 removed 132 net, C10
  and C11 added about 100 (the reading and opt-in rows, the cut mark, the
  marker rule), and the worker's edges grew it (the records, the kernel
  holds, the forwarded proof). The estimate counted the removals alone.
- **The cluster suites' clocks:** with C11 a window anchors only when a
  report lands before the close, so the suites that jumped every clock
  past a close in one step now step past the boundary first.
- **The cut bench** needed its agent to report every window, or its
  first crossing cuts nothing.
- Found, not fixed: the cut bench's process sometimes waits for good after
  printing (its store's release thread), on vos-core as here; killed by
  PID.

### 7.3: the review's fixes

Fable's review (`research/slice-7/7.3-fable.md`, fix-then-merge), folded
in six commits on `142554d4`: +592 −248 over 29 files.

- **M1, a kernel late past the patience:** a record whose kernel the node
  lacks waits for it, with one warning, and is proved under the right
  program id once it arrives; nothing is refused for patience and a lost
  kernel is never cached (`NO_PROGRAM` and `missing` go). The read
  records fold into the job table plus a window watermark (`read` and
  `unread` go), the proof asks and lost fetches into one map (`asked` and
  `unfetched` go); a rootless record is a refused job
  (`REFUSED_ROOTLESS`), so the table alone dedups. `1cb4c489`.
- **L1, the asks at the cut:** the representative's `asked` is a
  committed map, and a close reads the window's asks as the cut held
  them (the live rows and the cut's undo rows), so a replica that builds
  the cut late writes the same close and anchor row. A `Hooks::build`
  holds a replica's builds for the test. `2d8e529b`.
- **L2, Proven with the proof held:** `prove()` refuses a witness-less
  record with its own code (`REFUSED_UNWITNESSED`); a replica records a
  peer's `Proved` once it holds the blob, fetching it otherwise, and the
  leader proposes `Proven` only for a proof it holds. `1cb4c489`.
- **L3:** the ask writes `reading` only when it is below the window, as
  the representative's stored report does. `69191b6c`.
- **L4, the cut rule once:** `vos_wire::apply::Waits::cuts`, used by
  apply, the leader's marker (`cut_due`) and the cut model. `a7f7372f`.
- **L5:** documented (the `Admin::ReportEveryWindow` docs and
  `operations.md`): the issuer must be an agent other than the
  representative, whose own cuts carry no report of it. `c55fac89`.
- **L6:** `vos agent reports --agent A --every true|false`, over a new
  admin route (`POST /agents/{id}/reports`, `Operator::report_every_window`);
  `operations.md` points at it. `c55fac89`.
- **Info, pins and prune:** at open the worker drops the node's own pins
  that no job wants (`Host::held`, `Blobs::held_by_node`), so a crash leaks
  none; `prune` ages every job by its deadline (a rootless one by its
  window's) and no longer removes an absent agent's jobs, which its
  records would make again. `1cb4c489`, `18a71a31`.

**Tests:** worker: a kernel fetched late proved under its id
(`a_kernel_is_held_and_one_fetched_late_proves`), a witness-less record
refused (`a_witnessless_record_is_refused_for_it`), jobs outlasting their
agent's absence; testkit: `a_read_never_moves_the_reading_window_back`;
cluster: `a_late_build_closes_the_asks_its_cut_holds` (it fails with the
close reading the live asks alone: no anchor row of window 0); ingress:
`the_operator_sets_an_agent_to_report_every_window`.

**Unchanged:** the kernel program ids (`the_program_ids_are_the_repositorys`
passes). The representative's image changes (`asked` a committed map),
and the default agent's (L3).

**Gates** [measured]:
- `just check` green.
- The checker loop, seeds 7315 and 7316 with `CUTS_FULL`: green, 138 and
  112 s at load 25–35; 8 and 12 anchors, one a window, no evidence.
- `just e2e-chain`: the first run failed its latency gate at load 27–34,
  JAM's window-1 balance statement 253.4 s against 233.3 s (102.5 s of it
  after its proof, the testnet's blocks); the second, at load 19–31,
  green in 1,665 s: Kreivo 89.9 s, JAM 145.0–210.9 s, the tightest 0.8 s
  under its gate; one Kreivo anchor, 3.5 UNITS charged; the audit clean
  over 443 carriers.
- Found, not fixed: `liveness::idle_groups_send_nothing_but_the_pair_heartbeat`
  failed once in the whole cluster suite at load 16 (every group's term
  moved by one), and passed three times alone.

### 7.3: a recorded statement's witness kept

`prover::a_leader_change_submits_a_recorded_statement_once` failed about
3 runs in 5. Apply stripped a record's witness once its `Proven` applied
(M3, L2 above), so a follower's worker that read the record only after
that (its scan runs each second; the leader's model proof takes less)
held a job it could not prove; the new leader, the old one's proof gone
with it, refused the statement `REFUSED_UNWITNESSED` and never submitted
it. The record now keeps its witness until its window's roots age past
`MaxRootAge`, so any replica, a snapshot-installed one too, proves again a
statement whose proof was lost.

- **Tests:** cluster:
  `a_record_read_after_its_proof_is_recorded_is_proved_again` (the
  followers' workers held back until `Proven` applies; it fails 3 of 3
  without the fix); the leader-change test asserts the record kept whole.
  Worker: the mock keeps the witness, and a leader that never fetches the
  proofs proves all three again, each accepted once.
- **Carried:** a failover proves again every statement whose proof the old
  leader alone held, accepted ones too, since no replica learns of an
  acceptance; and the witnesses stay up to `MaxRootAge` (`SECURITY.md`'s
  table updated). A replicated acceptance (an input the leader proposes,
  which also drops the witness), or a venue query before proving a lost
  one again, would bound both. `Input::Proven`'s `attested` is no longer
  read by apply.
- **Gates** [measured]: the leader-change test 10 of 10 (twice: after
  the fix, and after the review's folds), the regression test 5 of 5 (3 of
  3 failing without the fix); `vos-node-prover`'s tests and the cluster
  suite (116) green; `just check` green on its second run (the first lost
  `snapshots::a_snapshot_stream_outlasting_the_leaders_deadline_goes_on`
  once at load ~20, a counter agent's snapshot stream, then 5 of 5 alone).
  Found, not fixed: one whole-suite run hung in
  `replication::an_agent_belongs_to_its_nodes_space` (its node threads
  gone, the test thread parked on a futex) at load 22; it passed 8 of 8
  alone and in the two suite runs since.

## Step 7.15: the device shape and its Poseidon2 chip

Branch `s7/7.15`, from vos-core `4e7b4982` (7.14 merged).

**Built:**
- **The Poseidon2 call's proof side** (pin H's `0x402`, dispatch 102):
  `core::ecall::ECALL_POSEIDON2`; the tracer serves it only when built
  `with_poseidon2` (`kernel::trace_device_kernel`), as pin H states it (64
  bytes at φ7, sixteen words each below p or the call traps; the first
  eight words of their permutation written at φ8; no other effect), since
  the runtime does not serve it before 7.9; the ledger records its 64
  reads and 32 writes, the registers' ledger its φ7 and φ8 reads.
- **The shared chip set's CPU** (`chips::CpuP2Chip`): format 35's CPU and
  one more main column after its own, `IsP2Ecall`, which the host-call
  continuation counts among the precompile selectors (dispatch 102); the
  call's row reads φ7 and φ8 below 2^32 and hands `(ts, φ7, φ8)` to the
  chip (`Poseidon2Call`), three fractions after format 35's. Format 35
  keeps `CpuChip`, its constraints exactly its own (one constraint body,
  the variant's selector an `Option`).
- **The Poseidon2 chip** (`chips::Poseidon2Chip`): one permutation a row,
  the S-boxes as `p2`'s (`a = y²`, `out = a²·y`, 284 columns, degree 3,
  unchained), the input's 64 bytes read and the output's 32 written through
  the ledger at the call's timestamp, each input word below p (its top byte
  below 128 by two `Range256` lookups, its bytes' sum not `3·255 + 127` by
  an inverse), each output byte range-checked and each output word
  canonical (top byte below 128, not p), the addresses `ptr + i` as byte
  limbs with boolean carries (the limbs sum to `ptr + i` whatever the
  carries, so a wrong carry gives the true address's ledger halves or
  halves outside `[0, 2^16)`, which join no group and start none). 527 main columns and 169 fractions,
  each its own interaction column (`Logup::Single`, the addresses being of
  degree 2): about 1,200 columns a row [measured, the build].
- **The device shape** (`vos_pvm_proof::device`, pin J): the shared chip
  set without the page boundary or the node's boundary chips, in
  `DEVICE_ORDER`, and four chips of its own:
  - `DeviceMemoryChip`, a row a byte the run touches: its address as 32
    bits, its region selected among the layout's five (read-only data,
    argument window, read-write data, heap, stack; preprocessed bounds,
    `page − first` and `end − 1 − page` as 20-bit distances), exactly one
    on a real row; its `ts = 0` write (the first touch, carrying
    `2·permission`, readable only for the read-only data and the argument
    window) and its closing read; the first touch of a data region's byte
    looked up in the data table, of any other region's zero. `MemoryChip`
    takes these pairs in place of the page boundary's (a device run's
    `side_note.device`), its constraints unchanged.
  - `DataTableChip`: every byte of the read-only and the read-write data's
    pages, `(address, byte)` preprocessed, a multiplicity column.
  - `DeviceBoundaryChip` (blinded): a row a register, the layout's entry
    value preprocessed; each register's entry write and its closing read at
    the halt's timestamp, the entry `(ts 1, pc 0)` produced and the halt
    `(final ts, HALT_PC)` consumed, φ9..12's final values handed to the
    `IoHash` relation. So the entry is the program's, the run halts, it is
    one segment, and no register but φ9..12 is public.
  - `DeviceIoChip` (its sum public): four rows producing `(r, φr)` for
    r = 9..12; the verifier recomputes its claimed sum from the io-hash
    (`masked::device_bound_sums`).
- **The shape is the program's** (pin J's witness-independent trace): the
  chips its code reaches (`device_chips_of_code`: every opcode's, each
  precompile an `ecalli` names), whatever a run takes; a log size each,
  chosen at install from a reference run and at least the masking's floor;
  the prover traces every chip at exactly its log size
  (`masked::DeviceSizes::Pinned`) and refuses a run that needs more
  (`ProvingError::Shape`).
- **The masked device segment** (`vos_pvm_recair::masked::device`):
  `install` computes the program (its chips, log sizes, layout and the
  preprocessed root they commit: code, data table, regions and
  permissions, entry registers) from the kernel alone; `prove_device`
  proves a run against it; `verify_device` takes nothing of the program
  from the proof. The transcript mixes the program's chips after the
  header (`MaskedFormat::program`, empty for the wrap and the node's
  segment, whose bytes are unchanged); the header already holds the
  format and the log sizes, the first commitment the root. The public
  values are the io-hash's 32 bytes.
- **The masked set generalized** (the review's M2): `masked::Components`
  over a `ChipSet` (`Node`, format 35's chips and its four public sums;
  `Device`, `DEVICE_ORDER` and DeviceIoChip's sum alone), so
  `public_sums` and the bound sums are the set's.

**The 7.14 review's hand-offs:** the program's chips mixed into the
transcript and verified against (`the_program_is_mixed_into_the_transcript`);
`bound_sums` and `public_sums` per chip set; the pinned shape on the device
prover (the node's masked segment keeps its floors; its shape is pinned per
class by 7.21's install record); the shape witness-independent
(`the_program_is_the_kernels`, `an_unused_chip_proves_at_its_pinned_size`);
the device shape's leakage gates, two witnesses at equal public values.

**Gates** [measured]:
- **Forgery** (`recair/tests/device/gates.rs`), each refused: a first touch
  of a data byte other than the table's (logup); a nonzero first touch of
  the stack or the heap (the prover, and forced the verifier's
  `OodsNotMatching`); a touch outside the regions (the same); a write to a
  read-only page (the same); a second segment (refused); a Poseidon2 output
  not the permutation's (constraint); an input word at or above p, p itself
  (constraint) and `2^31 + 5` (logup); a call without its row (logup). Each
  forged run is the kernel's own but for its one property: its machine's
  memory changed before the run (`kernel::trace_forged_device_kernel`,
  `seeded-masks`), or its record edited.
- **The public sum and the program:** an io-hash other than the run's and
  a forced proof blinding DeviceIoChip's sum refused; another program's
  chips mixed after the header, or its root, refused; six tampers refused,
  none a panic; a run past the program's shape refused by the prover; a
  chip set not the code's, or a log size under its floor, refused at
  install.
- **Acceptance:** the device kernel (witness input, the Poseidon2 call, the
  read-only and read-write data, the heap, the stack) on both channels,
  two witnesses under one program; under `heavy-gates`, at blowup 4 with
  43 queries (`h = 512`) and blowup 2 with 86 (`h = 1,024`) on Blake2s, R1
  in one attempt.
- **Degree audit** (`circuit`'s `the_masked_device_chips_pass_the_degree_audit`):
  every chip a device shape may hold, masked, at degree 3 or under; the
  shared CPU 826 constraints `[0, 17, 726, 83]`, the Poseidon2 chip 592
  `[0, 0, 330, 262]`, DeviceMemoryChip 86, DeviceBoundaryChip 11.
- **Leakage** (`recair/tests/device/leakage.rs`; 16 proofs a witness in
  `check`, `LEAKAGE_SEGMENT_N` under `heavy-gates`): the device shape states
  the io-hash alone, so two witnesses of the kernel (other 64 bytes read
  and hashed, one io-hash) have equal public values, slice 6's pairs with
  no deviation: witness indistinguishability (per field χ², pooled KS) and
  uniformity; neither the witness's bytes nor the call's output in a
  proof's bytes; no opening shared by two proofs of one run nor two
  witnesses' from one seed; a right guess reproduces DeviceIoChip's sum
  alone; one shape for both witnesses.
- **Format 35 byte for byte** for kernels without `ecalli 0x402`:
  `fixtures::the_fixtures_are_the_generators` and
  `the_fixtures_are_judged` pass, and `constants::` with every pinned
  value unchanged (in `test-proof`). ProgramMemory now commits the call's
  dispatch id 102 under every format, so a node kernel holding the call
  has another program-memory root; under format 35 it was and stays
  unprovable past the call, and pin H admits the call in device kernels
  alone.
- **`just check`:** green at `e67b7fee` (1,463 passed in 106 suites, the
  device's 22 among them; under a 12 GiB scope, `nice -n 10`,
  `CARGO_BUILD_JOBS=8`, other agents' runs on the machine, load 18–28).
- **`just test-proof`** (the leakage gates at their medium N, 64 proofs a
  witness on the device shape, `--test device` added to the recipe): green,
  574 passed in 49 suites, 42 minutes; the device's heavy acceptance and
  leakage tests 30 s; the carrier audit clean (451 `WrapRandomness`
  needles).

**The masked device shape of the auth statement, x86** [measured,
`spikes/s7-device/runs/x86-device-quiet.jsonl`; the statement as 7.0a
derived it, 19,192 steps, over its BLAKE2b tree; the Blake2s channel;
4 threads pinned to four P-cores, median of 5; quiet, load 1.7–1.8; the
`device` cell installs the kernel's program at the shape its run needs and
proves against it, verified; `floor` and `lean` are 7.14's `real` cells,
re-measured beside it]:

| cell | prove | CPU | peak | bytes | cells | columns | verify |
|---|---|---|---|---|---|---|---|
| device, 2:43:20 (h 512) | 1.67 s | 5.87 s | 2,803 MiB | 1,448,867 | 105.3M | 5,288 | 12.4 ms |
| floor, 2:43:20 | 1.65 s | 5.77 s | 2,756 MiB | 1,419,991 | 99.3M | 5,051 | |
| lean, 2:43:20 | 1.26 s | 4.35 s | 2,175 MiB | 687,281 | 72.8M | 1,950 | |
| device, 1:86:20 (h 1,024) | 1.30 s | 4.46 s | 1,811 MiB | 2,671,685 | 109.4M | 5,288 | 15.9 ms |
| floor, 1:86:20 | 1.27 s | 4.30 s | 1,770 MiB | 2,625,211 | 103.4M | 5,051 | |
| lean, 1:86:20 | 0.99 s | 3.30 s | 1,392 MiB | 1,220,214 | 76.8M | 1,950 | |

- **The device shape costs what 7.14's floor proxy did:** ×1.01–1.02 in
  time, memory and bytes. Its chips: the CPU at 2^15, BLAKE2b at 2^12, the
  memory ledger and the registers' at 2^16, DeviceMemoryChip at 2^13 (a
  row a byte the run touches), the data table at 2^13 (the statement's two
  data pages), the AND table at 2^16, every other at its floor; 20 chips,
  5,288 columns against the floor's 5,051 (the device's four chips against
  the node's three boundary chips, and the CPU's selector).
- **Against 7.14's lean shape** (the same session; 7.14's quiet table
  1.29 s, 2,153 MiB, 687,456 B at 2:43 and 1.02 s, 1,402 MiB, 1,219,144 B
  at 1:86): ×1.31–1.32 in time, ×1.29–1.30 in memory, ×2.1–2.2 in bytes.
  The difference is BLAKE2b and its AND table, which the statement over
  BLAKE2b still needs: lever 1 (7.17), the statement over the Poseidon2
  tree through the chip, removes them.
- **Pin J's budgets:** the proof fits 1.5 MiB at blowup 4 with 43 queries
  (1.45 MB) and not at blowup 2 with 86 (2.67 MB) until lever 1; peak
  memory 2.7 GiB and 1.8 GiB, past the 1 GiB budget (the CPU-side levers'
  target). Verification 12–16 ms on one x86 core's share, under pin J's 40
  ms; the install (program and root) 0.18–0.19 s.
- R1 in one attempt, 11 ms at 43 queries, 41 ms at 86.
- Under load (another agent's runs, load 18–28: `runs/x86-device-load.jsonl`)
  the same cells took ×4.0–6.5 longer (the floor cell at 2:43 10.69 s
  against 1.65 s), the device and floor cells within each other's noise.

**Where the plan was off:**
- **Pin J's shape needs boundary chips of its own,** not only a data table
  and a permission table. The node's register and program boundary chips
  publish the whole boundary (every register in and out, the pc and the
  timestamps), so a device proof built from them would publish its run's
  step count and every final register. The device shape replaces them with
  DeviceBoundaryChip (the entry as the program's preprocessed constants,
  the halt's pc a constant, everything at the halt blinded) and
  DeviceIoChip (the io-hash, the one public sum), beside DeviceMemoryChip
  and the data table: four chips besides the Poseidon2 chip.
- **The Poseidon2 call changes the CPU.** Pin H's `IsP2Ecall` selector is
  a CPU column and a precompile dispatch the continuation must count, so
  the shared chip set's CPU is not format 35's: `CpuP2Chip`, one column
  and three fractions more. Format 41 therefore re-pins the CPU too (7.21
  re-pins every program id anyway); format 35 keeps its CPU byte for byte
  (and its program ids, for kernels without `ecalli 0x402`).
- **The device chips cannot join `chip_idx`** before 7.21: its count is
  the wire's `SEGMENT_CHIPS` and the install record's `Shape`. Their
  indices continue past it (`device::device_chip`), the masks staying
  32-bit; 7.21 decides where the Poseidon2 chip sits in 41's.
- **The Poseidon2 chip is about four times pin H's "about 300 main
  columns":** the permutation is 284 (the 16 input words are the bytes'
  expressions), but the 96 byte accesses with their address carries and
  the range checks bring it to 527 main columns and 169 fractions, each
  its own interaction column (the addresses are of degree 2): about 1,200
  columns a row. A row a call, at the masking's floor of 2^11–2^12 rows,
  so about 5–10M masked cells [model] however few the calls: a lever for 7.17 (word-wide
  accesses, the address limbs as columns and paired fractions, or a
  pointer-alignment rule pin H does not have).
- **The program's log sizes need a reference run:** branch-free is
  necessary but not enough when a chip's rows follow the input's length
  (the witness input's bytes, the bytes touched); the install takes a run
  and the prover refuses one past it. A kernel's schema should state the
  input's bound its program is sized for (7.20).
- **The runtime does not serve `0x402` yet** (7.9): the proof's tracer
  serves it behind `with_poseidon2`, unpriced, the ABI exactly pin H's.

**Commits:** `4729d746` the Poseidon2 call's proof side, the shared CPU, the
Poseidon2 chip, the device's chips, the masked device segment and their
gates; `381da708` the spike's `device` cell (and the floor seam's hunk on
the device-aware ledger); `e67b7fee` the heavy acceptance, `test-proof`'s
device suite, the docs and `proving.md` §5 and §8; this record and the
runs.

**Review (Fable):** accept; L1–L4 folded
(`docs/design/research/slice-7/7.15-fable.md`). The carry argument in the
Poseidon2 chip's doc restated (the limbs sum to `ptr + i` whatever the
carry; BLAKE2b's address doc already holds, its limb 0 range-checked), and
DeviceMemoryChip's doc says two rows for one byte are harmless; this
record's load range and the format-35 caveat corrected; three gates added
(`a_non_canonical_poseidon2_output_word_is_refused`, an input inverted
from an output whose first word is 0, written as p: the prover and,
forced, `OodsNotMatching`; `a_trapping_run_is_refused`, logup;
`a_wrong_address_carry_is_refused`, every constraint held, logup) and
`a_second_segment_is_refused` asserting `Error::Logup`; the first and the
third fail with the output's inverse constraint dropped or the carry left
true [measured]; `LogupTraceBuilder`'s column writes one helper. Gates:
the device suite 24 of 24 (`heavy` gated off), the device degree audit,
`logup_trace_builder`'s bit-identity test, `fixtures::` (format 35 byte for
byte), `just check` green (1,466 passed in 106 suites; 12 GiB scope,
`nice -n 10`, 10 jobs).

## Step 7.16: the device parameters, measured

Branch `s7/7.16`, from vos-core `4a143e9f`; vos-core merged twice before
measuring (`8f58ae0c`, at `217c2982`, and at `44db9c32`), so every number
below is on the Stwo fork's `9e9b4ff6` (the SIMD Blake2s-M31 reduction
fixed). Stopped once for the owner's quota (2026-10-27) and resumed
(2026-10-30).

**Built:**
- **Blake2s-M31's `mix_bytes` packs four bytes a little-endian word**, the
  last zero-padded (`pcs.rs`, 7.10's review L2), so a boundary-state run
  of 296 bytes hashes 296 bytes, not 1,184; a unit test pins it against
  `mix_u32s` of the packed words and shows every byte of a run moving the
  digest. **Nothing moved:** no transcript calls it on that channel (the
  unmasked segment prover is `mix_bytes`' one caller, and no format there
  runs on Blake2s-M31; the masked transcripts, the credential's and the
  device's, mix their public values as felts), and `fixtures::` and
  `constants::` pass unchanged. The masked transcripts' felts (the device's
  io-hash, 32 M31s, 128 bytes hashed) are the settled encoding.
- **Format 43** (`format::DEVICE_PROOF`), registered and refused until
  ingress takes device proofs: masked (c), Blake2s-M31, blowup 4, 47
  queries, PoW 16, interaction PoW 8, affine DEEP batching, `h = 512`
  (`DEVICE_MASKING`), **110 conjectured and 62.82 proven bits** on its
  reference. **37 retired** unregistered. `pvm/proof/SECURITY.md`, the
  module's notes, pin J and `proving.md` §8 say so.
- **The masked device reference** (`format::DEVICE_REFERENCE`): the device
  set with every chip a device program may hold at 2^17 rows, masked under
  (c): columns at degree bound 2^18, the composition whole at 2^19, 7,548
  DEEP values, 4,292 constraints, 155,058,176 fractions (each chip's masked
  row's, the blinding's among them), the widest relation's 265 limbs;
  derived from the built set by `recair/tests/device/format.rs`, which also
  pins 43's bits, one query fewer under 62, the least queries by blowup,
  PoW and batching, the candidates' bits, and that a program with every
  chip smaller counts more (uniform sizes 2^10 to 2^16; subsets and mixed
  sizes are argued term by term in the review, not tested).
- **`device::DEVICE_MAX_LOG_SIZE` = 17**, enforced by `install` and by
  `device_format`, which the prover and the verifier both take: a program
  with a taller chip, or one under its floor, however it was made, is
  refused (`a_program_outside_the_formats_count_is_refused`), so the count
  holds for every program 43 proves. No headroom: the auth statements'
  ledgers are at 2^17 already.
- **`tools/phone`'s device cells** (`vos-phone device`, `device.rs`):
  `statement/blowup:queries:pow/channel` (`b2sm31`, `b2b`), each in a child
  process: install from a reference run, a warm-up, timed traces and
  proves, each proof verified, bytes (postcard), peak resident, R1, columns
  and cells, by chip. The kernels and their witness inputs are files
  (`--kernels`); the pool's stacks are 16 MiB (below).
- **The spike** (`spikes/s7-device`): the guest's `auth_p2`, pin J's
  device kernel over the credential actor's Poseidon2 tree through
  `0x402` (its public words auth's `CredentialPublic`, its output empty,
  the path walked with masks; 36 compressions); the patch admits `0x402`
  in derivation (the derivation refuses it in kernels); `harness kernels`
  writes `kernels/{b2,p2}.{kernel,input}`, each traced to its halt;
  `scripts/x86-params.sh` and `scripts/p4.sh` (the session).

**The counts** on the reference [measured, the security tool; proven bits
by powers / affine, conjectured]:

| candidate | powers | affine | conjectured |
|---|---|---|---|
| blowup 2, 86 queries, PoW 20 | 61.77 | 62.77 | 106 |
| blowup 2, 87, PoW 20 | 62.20 | 63.25 | 107 |
| blowup 4, 43, PoW 20 | 62.09 | 62.83 | 106 |
| **blowup 4, 47, PoW 16 (43)** | 62.01 | **62.82** | **110** |
| blowup 8, 29, PoW 20 | 62.56 | 63.33 | 107 |

The least queries clearing 62: blowup 2 at PoW 20, 87 by powers, 85
affine; blowup 4, 43 at PoW 20 and 47 at PoW 16; blowup 8, 29.

**x86** [measured, `spikes/s7-device/runs/x86-params.jsonl`,
`x86-params-extra.jsonl`; `vos-phone device` on the fixed fork pin; 4
threads pinned to four P-cores (1, 3, 6, 8), 8 over the six P-cores'
twelve; 5 reps after a warm-up (the p95 of 5 is their maximum); the
Blake2b-256 cells one rep, no warm-up; masks from the OS (the x86 binary
was `just phone`'s seeded build, whose seed only the credential cells
take: 5 distinct proofs a cell; the header's `format` is the credential
format's, every cell's 43 whatever its parameters); load 3.3–10.6 (other
agents' runs; the extra file at 7.7–10.6), so about ±15%]; `p2` the auth statement over the Poseidon2
tree (18,733 steps), `b2` over the vos-tree (19,240):

| cell | threads | prove p50 / p95 | peak | bytes | verify | R1 |
|---|---|---|---|---|---|---|
| p2, 2:86:20 | 4 | 2.70 / 2.87 s | 2,340 MiB | 3,234,956 | 32.0 ms | 76 ms |
| p2, 2:87:20 | 4 | 2.69 / 2.92 s | 2,351 MiB | 3,278,981 | 32.6 ms | 94 ms |
| p2, 4:43:20 | 4 | 2.78 / 2.92 s | 3,396 MiB | 1,750,427 | 23.2 ms | 22 ms |
| **p2, 4:47:16** | 4 | **2.64 / 2.77 s** | 3,400 MiB | 1,890,322 | 23.6 ms | 25 ms |
| p2, 8:29:20 | 4 | 4.07 / 4.15 s | 5,688 MiB | 1,254,233 | 21.4 ms | 8 ms |
| p2, 2:86:20 | 8 | 1.84 / 1.89 s | 2,404 MiB | 3,247,820 | | |
| p2, 2:87:20 | 8 | 1.89 / 2.15 s | 2,392 MiB | 3,281,054 | | |
| p2, 4:43:20 | 8 | 2.00 / 2.73 s | 3,453 MiB | 1,740,471 | | |
| p2, 4:47:16 | 8 | 1.93 / 2.36 s | 3,475 MiB | 1,895,246 | | |
| p2, 8:29:20 | 8 | 3.72 / 4.55 s | 5,698 MiB | 1,251,166 | | |
| b2, 2:86:20 | 4 | 2.12 / 2.20 s | 2,244 MiB | 2,706,930 | 24.8 ms | 82 ms |
| b2, 4:43:20 | 4 | 2.88 / 2.99 s | 3,566 MiB | 1,465,162 | 19.7 ms | 24 ms |
| b2, 4:47:16 | 4 | 2.84 / 2.98 s | 3,546 MiB | 1,589,518 | 20.2 ms | 26 ms |
| b2, 8:29:20 | 4 | 4.50 / 4.55 s | 6,278 MiB | 1,058,938 | 17.4 ms | 10 ms |
| p2 on Blake2b-256, 2:86:20 | 4 | 22.2 s (one) | 2,245 MiB | 3,248,128 | 30.1 ms | |
| p2 on Blake2b-256, 4:43:20 | 4 | 46.2 s | 3,372 MiB | 1,746,058 | 33.0 ms | |
| p2 on Blake2b-256, 4:47:16 | 4 | 48.5 s | 3,350 MiB | 1,888,115 | 23.7 ms | |
| p2 on Blake2b-256, 8:29:20 | 4 | 90.5 s | 5,647 MiB | 1,249,983 | 17.6 ms | |

Configurations are blowup : queries : PoW. The trace takes 6–10 ms, the
install (program and preprocessed root) 0.22–0.62 s; verification
17–42 ms in the prover's pool (under pin J's 40 ms at the pin, not
measured on one core).

**The shape and the breakdown** [measured; p2 at 8:29:20 (floors 2^10)
and b2 at 4:43:20 by chip, each component's committed columns and their
cells at the masked level, before blowup (salts, `R` and the composition
not counted); at the pin's floors of 2^11 the floor chips' shares, BLAKE2b's
among them, about double; perf over p2 at 4:47:16, 4 threads, load 9.6]:
- p2's 21 chips, 6,495 columns: **the CPU 54% of the cells** (2^15 rows,
  785 columns), the memory ledger 17% (**2^17 rows**), the registers' 9%
  (2^16), **BLAKE2b 7% at its floor but 3,136 columns**, program memory 3%,
  **the Poseidon2 chip 3% and 1,207 columns**, the AND table 2% (2^16),
  every other at most 2%. b2: 5,288 columns, the CPU 45%, BLAKE2b 23%
  (2^12), the ledger 14%.
- perf: Blake2s compression (the Merkle trees, every column lifted to the
  lifting height) 36%, the FFTs about 10%, the constraint and logup
  evaluation about 10%, rayon's bridged closures (interpolation,
  extension) about 20%, the witness digest's BLAKE2b 3%.

**The pin: format 43 at blowup 4, 47 queries, PoW 16** (affine; 110 /
62.82). **No candidate meets both of pin J's budgets on the auth
statements**: every one peaks at 2.2–6.3 GiB on x86 against 1 GiB. On
bytes, the Poseidon2 statement's proofs fit 1.5 MiB only at blowup 8 (1.25
MB), the BLAKE2b statement's at blowup 4 with PoW 20 (1.47 MB) and blowup
8. Blowup 8 is the slowest (×1.5) and peaks near 5.7 GiB (about 6.5 GiB
on the phone's mimalloc build, past what the phone's 7.5 GB leaves a
process); blowup 2's proofs are 2.7–3.3 MB, about twice the budget, more
than any one lever removes. **On time the candidates at blowup 2 and 4
tie** within the noise (p2 on 4 threads 2.64–2.78 s, on 8 1.84–2.00 s,
blowup 2 slightly ahead there; b2 favours blowup 2 by 25%, 2.12 against
2.84 s), so the pin rests on bytes, memory and the grind: blowup 4's proofs
are within about 20% of the budget (p2 1.89 MB; b2 1.59 MB at PoW 16, 1%
over, 1.47 MB at PoW 20) and fall under it once the io-hash's BLAKE2b
leaves the shape (about 1.0 MB [est], below); PoW 16's grind has the short
tail (on the phone PoW 20's 95th percentile is 69–72 ms, PoW 16's 6–7 ms,
7.12's P2) for 4 more queries and 8% more bytes; and it is format 44's
parameter set, one grind and one set for both formats. The trade, taken:
PoW 16 puts the BLAKE2b statement's proof 1% past 1.5 MiB where PoW 20
keeps it under. Format 43 stays reserved; 7.17's lever 4 counts again on
the lighter shape.

**Session P4: not run.** The Fairphone 6 was not on USB when this step
reached it (2026-10-30 17:40–19:00: `adb devices` empty, the phone not in
`lsusb`, an adb server restart changed nothing). Ready to run:
`just phone` built `vos-phone-timing` (SHA-256 `ddeefcf6…750d`) with the
device cells; `spikes/s7-device/scripts/p4.sh target/phone/vos-phone-timing
spikes/s7-device/kernels <out>` runs the session (three rounds of p2 at
every candidate at automatic threads, one on the four big cores, one of
b2, one Blake2b-256 cell; battery at least 50% and below 35.0 °C before
each round, waiting up to an hour; it removes `/data/local/tmp/vos-p4`).
The pin is therefore x86's; the phone may move it only between blowup 4
at PoW 16 and at PoW 20 (the same bytes and memory), which the grind's
tail already decided at 7.12.

**Where PG2's 1 s stands:** the pin proves the auth statement in 2.64 s
on four x86 P-cores (1.93 s on 8) under load 3–5; at 7.12's ratio (the
phone at automatic threads about 3.8× x86 on four P-cores, 2.9× on its
big cores) that is **about 7.5–10 s on the phone [est]**, against 1 s, and
3.4 GiB on x86 against 1 GiB. 7.15's quiet 1.67 s for b2 at 4:43:20 is
now 2.88 s at load 3–5 with the memory ledger at 2^17 (the same cells
within 8%): the load accounts for most of it, unmeasured quiet here. PG2
needs about ×8–10 from the levers; the plan's outlook (0.75–1.7 s) assumed
lever 1 removes BLAKE2b and its AND table, which it does not (below).

**The levers, ranked by the breakdown:**
1. **The io-hash through Poseidon2** (not in 7.17's list): the device
   kernel's io-hash is BLAKE2b, so BLAKE2b (3,136 columns) and its AND
   table stay in every device shape, the Poseidon2 statement's too. They
   are 48% of p2's columns: the Merkle hashing, 36% of the time, goes
   with the columns, not the cells, and so do the bytes. Moving the
   io-hash (pin J's, pin I's words) onto Poseidon2 for device kernels: about
   −45% bytes (1.89 → about 1.0 MB at the pin) and −15–20% time [est]. A
   design change for 7.17's first day.
2. **A lean kernel (lever 3):** the CPU is 54% of the cells at 2^15 rows
   for 18,733 steps; under 16,384 steps the CPU and program memory halve
   (about −30% of the cells), and fewer argument copies take the ledger
   from 2^17 to 2^16 (−8%). The Poseidon2 statement takes as many steps as
   the BLAKE2b one: decoding and copying 1,189 bytes of arguments and the
   path's masks, not the hashing.
3. **The CPU split (7.18):** the CPU's 785 columns a row are the largest
   single share whatever its rows.
4. **The Poseidon2 chip's width:** 1,207 columns for 36 rows at its floor,
   19% of p2's columns (word-wide accesses, paired fractions; 7.15's note).
5. **Threads by core class (lever 2):** 22% at PG1 on the phone; to be
   measured at P5.
6. **Parameters again (lever 4):** on the Poseidon2 statement blowup 2
   and 4 tie in time (on the BLAKE2b one blowup 2 is 25% faster); the floor's share is small at the device's sizes (the
   masking's floors are 2^10–2^12, the tall chips 2^15–2^17), so a tighter
   `h` buys little here; on a lean shape the floor's share grows.
Memory is the second gate: every candidate is 2.2–6.3× the 1 GiB budget on
x86, and only the cells' reduction (levers 1–3) and the masked prover's
working set bring it down.

**Where the plan was off:**
- **Lever 1 does not remove BLAKE2b:** the kernel's io-hash keeps it and
  its AND table in every device shape. **The Poseidon2 statement is not
  cheaper than the BLAKE2b one** on this AIR: 6,495 columns against 5,288
  (the Poseidon2 chip's 1,207 added, BLAKE2b's kept at its floor), so its
  proofs are larger (1.89 against 1.59 MB at the pin) and at blowup 2 it
  is slower (2.70 against 2.12 s); at blowup 4 it is faster (2.64 against
  2.84 s). S21's statement is lighter only once the io-hash moves.
- **The memory ledger takes 2^17 rows** (a row a byte touched), not 2^16
  (7.15's record); so the reference is at 2^17, `install` refuses taller,
  and pin J's "at most 2^16 steps" bounds the CPU only.
- **No candidate meets both budgets;** memory is 2.2–6.3× over on x86.
- **Blake2b-256 is 8–22× slower** than Blake2s-M31 on the prover's trees
  (the fork's Blake2b Merkle hashing has no SIMD path): 22–91 s against
  2.6–4.1 s; the comparison channel is out of the running for phones.
- **A stack overflow at blowup 8 on 8 threads:** the prover's nested
  rayon joins overflowed a worker's default 2 MiB stack about once in 18
  proves (gdb: a chain of `bridge_producer_consumer::helper` and
  `join_context` frames); none in 24 at 16 MiB. The bench's pool sets 16
  MiB; `vos-device`'s pool must too before it proves device kernels (7.20).
- **The derivation refuses `0x402` in kernels:** device kernels need a
  derivation path that admits it (pin H's "device kernels and handlers
  alone"); the spike patches it. For 7.20.

**Review (Opus):** nothing high; the reference an upper bound term by
term (levels maxima, constraints and fractions sums, the global relation
width, affine batching ignoring the batch's size; the logup term near 97
bits, not binding), `h = 512` enough for every device column (at most two
offsets), affine batching what both sides run, the `mix_bytes` change
unused by any pinned transcript. Folded: M1, the cap enforced only at
install: `device_format`, which the prover and the verifier both take,
now refuses a log size above `DEVICE_MAX_LOG_SIZE` or under its floor
(the prover with `TraceShape`, the verifier with `Format`), and a gate
shows it for a program made by hand; M2 and M3, the record's and the
docs' pin claims (the BLAKE2b statement fits at blowup 4 with PoW 20; the
times at blowup 2 and 4 a tie, the pin resting on bytes, memory and the
grind); L2, a Blake2s-M31 run must be whole words (asserted, the 296-byte
boundary run is), `transcript.rs`'s doc; L4–L6, the record's numbers and
provenance; L7, pin J's shape bound restated as the rows' cap. Not taken:
L1 (`mask_rows` lowers a component's `h` to the format's without error; no
device column needs more at 47 queries, and the cap is pre-existing);
L3 (the bound over chip subsets and mixed sizes is the review's
term-by-term argument, not a test); `DeviceProgram`'s fields stay public
(the gates build programs by hand; the checks are in `device_format`); a
check that the format is the registry's 43 waits for ingress (7.20),
since the bench and the gates prove under formats of their own.

**Gates** [measured; 12 GiB scope, `nice -n 10`, 6 jobs, other agents'
runs beside]: the device suite 29 of 29 and `vos-pvm-proof`'s format and
`pcs` tests; `just check` green at `3a95da42` (1,646 passed in 125 suites;
its first run caught a clippy type and the formatting, fixed); `just
test-proof` green at `3a95da42` (582 passed in 50 suites), `fixtures::`
and `constants::` among it
(nothing moved by `mix_bytes`).

**Commits:** `a69e76b0` (work in progress, at the quota stop),
`8f58ae0c` the first merge, `a4fdb6d4` the pin and the measurements, the
second merge, `d421c7ee` and `583b6c5a` this record and its formatting,
then the review's folds.

## Step 7.10b: the node API and the gateway

Branch `s7/7.10b`, from vos-core `ad1ff380`. The brief, `node-api.md`,
revised with Fable's review (`research/slice-7/7.10b-brief-fable.md`,
fix-then-implement): M1–M8 and L1–L15 folded, the questions answered in
its §10 (Q-C, s4 as a git dependency from its `vos` branch, the owner's).

**Built** (C1–C9 of the brief's plan; C10, deleting the node's HTTP,
waits on S50's gate):
- **`vos-api`** (`node/api`): the frame (a `u32` LE length, a `u16` kind,
  on a byte stream a `u64` id), a sans-IO `Reader` that checks each header
  before keeping its body (length, kind, a relay's set, the kind's limit),
  `Kind` and its table, `FrameError` with `Unavailable`, `Operated` naming
  its node; a multiplexed client over any byte stream and a QUIC client.
  `Rejection::Operator` (index 10) and `cap::MAX_ELF` in `vos-wire`; fuzz
  targets `api_reader` and `operated_decode` in `just fuzz`.
- **`vos-http`** (`node/http`): the HTTP server made runtime-neutral, the
  public TLS, and the route table both fronts run.
- **The node**: one handler (`api::handle`), its own HTTP a translation
  onto it; the unix socket (`api_socket`, a lock file against twins, the
  file bound beside its path and moved in with its mode); the QUIC endpoint
  on its own port and thread (`api_listen`, `gateways`, ALPN `vos-api/1`);
  `api_connections`, `api_in_flight`, a frame's deadline, `floor_waits`;
  signed operator requests on every transport (`operators`,
  `local_operator`, `operator.key` and `operator.pub`), the nonce recorded
  in one step and synced before the command, the reads recording none.
- **The client**: `unix:` and `quic://` targets, a transport of HTTP's
  requests over either (translated by the route table), redirects over the
  API by the client's routes, the operator signing for one node (the
  envelope as the body, or in the `Authorization` header over HTTP),
  `Trust::Gateway`. `vos` signs operator commands with `operator.key`.
- **`vos-gateway`** (`node/gateway`): HTTP byte for byte onto the nodes'
  APIs, public TLS, limits per address, leader-aware routing; with its
  `ssh` feature (`just test-gateway-ssh`), s4's SSH port and the `vos-api`
  subsystem, and `app.key`.
- **s4**: the named-subsystem hook, `bd3c435` on s4's `vos` branch, under
  s4's gate, now on codeberg (`Virto/s4`); the gateway pins it by git rev
  at `cee80d95` (the hook and an advisory fix) behind its `ssh` feature,
  off by default: s4's crates ask Rust 1.94.1, which the workspace's
  nightly builds with `--ignore-rust-version`.
- **`vos-scale`**: the drivers over QUIC (one connection a node, a stream
  a request, the deployed `driver.key` listed in `gateways`), the
  coordinator signing with the deployed `operator.key`, each node's `api`
  port, and the gateway's cost, a row of its own. The checker's processes
  and the served cluster reach their nodes over the API's sockets as their
  options and seeds choose; a kill suite's client calls through a gateway.

**Tests:** the brief's 1–18 (with the Fable fold: the install-size
budget and the head-time refusals at the gateway and over QUIC, a dead
upstream delaying no other's requests, `NotLeader` followed, a client's
pin across a 421, an install in the corpus): the codec's pins and proptests; each kind's
limit from its header, unknown kinds, truncated frames, out-of-order
answers, the in-flight bound, the deadline and the connections, a stale
socket and its twin (`tests/ingress/api.rs`, `quic.rs`); every operator
refusal on both transports, two copies at once, a replay after a restart,
the nonces' bound (`operator_api.rs`); one client and operator over HTTP,
the socket and QUIC (`transports.rs`); the differential corpus, a signed
call altered, the burst's 429, a 413 that reaches no node, redirects
followed and operators routed by their node, a client pinning the
gateway (`node/gateway/tests/gateway.rs`); the `vos-api` subsystem's relay
set, `Unavailable` keeping the channel, sixteen in flight
(`node/gateway/tests/ssh.rs`); the scale pool over QUIC against a node.

**Measured** (test 16): the localhost smoke over the node API, three
nodes and a driver on this machine (`--exclude n4`: four would not fit
the disk check), 20 s at 50 calls/s: 1,016 sent, 0 errors (the 7
`cut_read`s `Attesting`, a 20 s run being shorter than a window), p99
32.8 ms; the gateway's row: 173/500 µs p50/p99 through it against
144/721 µs to the node's API (a smoke's numbers only).

**Review (Opus):** no authority leak found (operator commands run only
signed, or behind the node's own token; no node other than the one an
envelope names; the relay set enforced from the header). Folded: H1 (the
multiplexed client's cancelled write could leave half a frame on a shared
socket: requests now queue whole frames for a writer task); H2 (one
address could stall a node's sockets: SSH channels and in-flight frames
take places among their address's, each frame a token of its rate, and
the node bounds queries waiting for a floor); M1 (a frame's deadline runs
from its own first byte); M2 (QUIC Retry, handshakes bounded and timed,
connections counted after the handshake); M3 (the re-sign after `Expiry`
keeps its nonce); M4 (the envelope checked from its fixed prefix before
it is decoded, off the node's thread); M5 (IPv6 by /64, the buckets'
sweep bounded); L2, L3, L5, L6, L9, L10. Left: L1 (a nonce forgotten as
the wall clock passes its expiry could be taken again if the clock steps
back past it), L4 (dials under the upstream's lock), L7 (a node's closing
frame error passed on an SSH channel left open), L8 (no write deadlines,
as before), and M4's head-time refusal of an install-size body at the
gateway and a budget of large bodies in flight; all but L7 and L8 folded
with Fable's review, below.

**Gates:** `just check` green after the fold (EXIT 0; 12 GiB scope, `nice -n 10`, 6 jobs), `just test-gateway-ssh` green.

**Review (Fable):** fix-then-merge; M1, M2, L1, L2, L3, L5, L6, L9, L10,
L11, L12 folded (`research/slice-7/7.10b-fable.md`). No authority found
beyond relaying, on any transport; the two mediums were the public
face's availability:
- **M1** (no budget for install-size bodies: one address could hold
  4 GiB of the gateway's memory with no key): `vos-http`'s
  `Limits::large`, at most four bodies past the ordinary limit held at
  once from every connection, a request past them answered 503 from its
  head, its body unread, on the node's own HTTP too; and a server's head
  hook, with which the gateway answers an operator's route with no
  `Operated` header 401, and one signed for a node behind no upstream
  421, before any body is read, as the whole request would be (L5: its
  429 too). This was the gate before the gateway faces the internet; it
  is closed.
- **M2** (dials under the upstream's lock: one dead node delayed a share
  of every read by its dial in turn): a dial holds no lock a request with
  a connection open waits on, one at a time per upstream; a failed dial
  marks the node down for a backoff (1 s doubling to 8 s), answered at
  once while it lasts; reads in turn, and calls to a learned leader, skip
  a node down or slow to dial while another is ready; a failed request
  clears only the QUIC connection it used.
- The lows: a nonce forgotten only past its expiry and the 120 s horizon
  (L1); the socket's detached requests after a frame error noted in its
  module and `node-api.md` (L2); QUIC handshakes bounded per address, 8
  of the 64 (an IPv6 /64), and `api_listen` to be firewalled to gateways
  and drivers (L3); at most four large bodies across the node's socket
  and QUIC, the socket reading the next only as one ends, QUIC answering
  `Unavailable` from the header (L6); tests (L9): a stand-in node
  answering `NotLeader` followed to the leader it names, then learned (a
  live cluster answers `NotLeader` only while its leader changes:
  followers forward calls and read indexes), a successful install in the
  differential corpus, and a client pinning a gateway following a 421 to
  a second gateway under the same key; `Operator::send`'s resend
  answering `Replayed` when the first copy ran, in its doc (L10);
  `Kind::operator()` naming the table's kinds (L12).
- **Open:** L7 (a node's closing frame error passed on an SSH channel
  left open: only under version skew) and L8 (no write deadlines), both
  acceptable for the step; the review's hand-offs to 7.11 (`Credentialed`
  and the verification budget) and 7.13 stand.

**Gates after the Fable fold:** the touched suites (`vos-api` 17,
`vos-http` 3, the node's `ingress` `api::`, `quic::`, `operator_api::`
and `transports::` 20) and the gateway suite (10, with the `ssh` feature
on s4's codeberg rev 3 more) green; `just check` green at `89becd5d`
(EXIT 0, 1,552 passed in 121 suites; 12 GiB scope, `nice -n 10`, 6
jobs), `just test-gateway-ssh` green at `7c04fb40`.

**Not done:** C10 (S50's gate).

## Step 7.9: the Poseidon2 host call and the credential actor

Branch `s7/7.9`, from vos-core `ad1ff380`.

**Built:**
- **The call in the runtime** (pin H's `0x402`): `vos_pvm::precompile::POSEIDON2`
  at `POSEIDON2_GAS` (2,400), computed by `vos-pvm-poseidon2`'s permutation
  (`poseidon2_compress`, which the proof's tracer now calls too: one
  function on bytes). The refine host serves it in place for the outer
  machine; a word at or above p, p itself included, or an unreadable input
  or unwritable output, panics the machine on the call's own counter, with
  nothing written. It joins `REFINE_HOST_CALL_ALLOWLIST`; `is_kernel_call`
  does not take it (node kernels prove under format 35, which has no
  Poseidon2 chip), nor does `surface::kernel`, so `derive` still refuses a
  kernel that calls it.
- **The agent and the wire:** `vos_wire::abi::precompile::POSEIDON2` at
  the same price; the agent serves an inner machine's call (its input read,
  each word checked below p or the actor's step trapped, the output written
  at φ8 through the machine's tracked writes, the written page priced at
  φ8's 32 bytes), computing it through its own `0x402` call: natively on a
  VOS node, in software on JAM. `precompile::serving(id)`: the batch's
  gas the agent takes for serving a call, `POSEIDON2_SERVING` (60,000) for
  this one, since its software permutation costs JAM about 38,600 against
  BLAKE2b's 17,100. A kernel's run serves the BLAKE2b precompile alone.
- **The guest shim:** `vos_pvm_precompiles::poseidon2_compress(left,
  right)` and `poseidon2_compress_block`: the call, and on `WHAT`
  `vos-pvm-poseidon2`'s permutation, which panics (traps the guest) on a
  word at or above p as the call does. The proof's tracer charges the
  call's price when it serves it (`with_poseidon2`), as the runtime does.
- **`vos_wire::credentials`** (`identity-and-authority.md` §6,
  `proving.md` §8): the six tags pinned (`Tag`, `#[repr(u8)]`, each `t`
  checked against `BLAKE2b-256("vos/p2/" ‖ name)`, distinct and nonzero),
  `W`, a digest's words (a word ≥ p refused), `C` through the shim,
  `leaf`, the 33 empty subtrees pinned (`EMPTY`), `root_of`, `Path` (root,
  slot, 32 siblings as 1,024 bytes) with `Path::proves`, the `Ring` of the
  last 64 `(root, since)` with `record` and `accepts` (the freshness rule:
  newest, or superseded at most `ROOT_MAX_AGE` before; a root held twice
  judged by its later entry; `RootRefusal::{Unknown, Stale}`),
  `defaults::ROOT_MAX_AGE` (10 minutes), the table names and the ring's
  key, and `CredentialError`. Ingress and apply (7.11) and the device
  library (7.12) read these.
- **`vos-credentials`** (`agent/credentials`, its own guest workspace,
  `just build-credentials`, in `check` and `test-agent`): the actor and its
  handlers in `lib.rs`; its rows `slots`, `nodes`, `free` (ordered),
  `invites` and `ring`, its struct `handle`, `next`, `count`. `found(handle)`
  (once, never zeros; writes the ring's first root, the empty tree's), then
  `enroll`, `enroll_many` (at most 256; one refused, none enrolled),
  `invite`, `claim` (any caller, until the expiry, `t ≤ expires_ms`),
  `revoke` (also withdraws an invitation), all but `claim` under
  `registrar`; the queries `path`, `root`, `handle` and `count`. A write
  sets its leaves and recomputes each node above them once: 33 calls an
  enrollment, 32 a revocation, and an `enroll_many` of 256 contiguous slots
  535; a node equal to its level's empty subtree is deleted, not kept.
  `enroll` and `claim` take the lowest freed slot through the SDK's new
  `Table::first` (a scan as small as one row); `enroll_many` takes only
  slots never used, the re-seed's case.

**Tests** (`agent/testkit/tests/agent/credentials.rs`, the default agent
on the node's hosts; and the runtime's, the wire's, the shim's and the
bench's):
- the tree equals a reference built from scratch from `proving.md` §8
  alone (the reference's own tag from BLAKE2b, its own empty subtrees,
  every level rebuilt), over twelve batches of random enrollments, `enroll_many`s
  and revocations, on a VOS host and on the JAM-only host: the two refine
  every batch to the same work result byte for byte and accumulate to the
  same storage; each slot the reference's; the root and `since` the
  reference's and the batch's; every member's path the reference's,
  verified by the reference's walk and by `Path::proves`, and refused for
  another member;
- freed slots reused lowest first, whatever order they were freed in, then
  the lowest never used;
- the refusals (`Unfounded`, `ZeroHandle`, `Founded`, `NotADigest`,
  `Enrolled`, `NotEnrolled`, `TooMany`, an `enroll_many` with a duplicate
  enrolling none, `Forbidden` for a caller without `registrar`); an
  invitation claimed by any caller before its expiry and refused after it,
  once, a claim of a digest not invited, a withdrawn invitation; the ring's 64
  entries read from the stored row, one a batch, and judged `Unknown` and
  `Stale` by `Ring::accepts`;
- an `enroll_many` of 256 within one handler's gas;
- a word ≥ p traps the live call: on the refine host, on both backends,
  at the call's counter with nothing written (p at words 0 and 15,
  `u32::MAX`); through an actor (the counter's `compress`) on a VOS host
  and on the JAM-only host, `Failure::Trapped`, the served call the
  reference's at one price on both; the runtime's `execute` refusing p,
  `2^31` and `u32::MAX`, and unreadable or unwritable ranges;
- the bench's cross-host agreement: the `poseidon2` guest's chain on a VOS
  host, on a JAM-like host answering `WHAT`, and the reference's.

**Measurements** [measured]:
- **The price** (`precompile native`, x86, the machine loaded by other
  agents' runs, load 9–27): serving a Poseidon2 compression natively took
  1.2–1.7 µs, 3,640–5,190 time-stamp-counter cycles (best 3,640), 2.6–4.4
  times a BLAKE2b compression's in the same run (BLAKE2b 884–1,980 here,
  520 on the quiet reference machine): about 1,800 cycles quiet [est].
  `POSEIDON2_GAS` is 2,400, four BLAKE2b prices, rounding up as
  BLAKE2b's 600 does its 520. The scalar permutation is
  `vos-pvm-poseidon2`'s reference; its packed form serves sixteen at once,
  no help to one call. In the guest, in software on `WHAT`, a compression
  costs 37,585 gas, against 15,874 for BLAKE2b's.
- **The agent's serving** (`serving_a_precompile_costs_the_agent_its_bounce`):
  a Poseidon2 call costs an actor 3,121 gas, 2,400 of it its price, on
  both hosts; serving it costs the agent 5,756 on a VOS node and 38,630 on
  JAM (BLAKE2b's: 4,250 and 17,127), under `POSEIDON2_SERVING`'s four
  fifths.
- **The actor:** an enrollment 4.09M gas, a revocation 4.06M, an
  `enroll_many` of 256 78.3M (against the 100M a handler may request): the
  rows dominate (a `put` 64,000, a `get` 30,000), the 33 calls about
  100,000. With a free-table scan a member it took 98.9M.

**Where the plan was off:**
- **The software permutation costs about 37,600 gas,** not pin G's
  "about 15,800 instructions"; natively the call costs about four BLAKE2b
  compressions, so its price is 2,400, not BLAKE2b's 600. Pin G, pin H,
  `proving.md` §8 and identity §6 now give the measured numbers.
- **One serving charge did not fit both calls:** `PRECOMPILE_SERVING`
  covers a BLAKE2b compression in software on JAM (17,100), not a
  Poseidon2 one (38,600); the serving is now per precompile.
- **A revocation is 32 calls,** not 33: its leaf is the empty one.
- **The install cannot take the handle:** an actor's state is made by
  `new()`, with no arguments, at its first load; `found(handle)` is the
  install's step, and the actor takes no write before it.
- **`enroll_many(256)` fits a handler only batched, and only on fresh
  slots:** 256 enrollments one at a time would take about 1G gas; one
  write over all their leaves shares the upper nodes, but 256 freed slots
  scattered over the tree share few (about 230M [est]), so it takes the
  slots never used, as a re-seed into a new space's tree does. On a
  JAM-target instance a step's 128 rows bound it to about three members a
  call.
- **Left to 7.11,** which reads them: the schema's credential-actor mark
  (`#[actor(credentials)]`), the system row `credentials → instance`, and
  `Failure::Credentials`; this step's actor is installed and called as any
  library actor.

**Review (Opus):** no high finding; all folded. M1, a free-table scan a
placement (a 4 KiB scan page, about 0.4M gas from a large free table) and
scattered freed slots putting `enroll_many(256)` past its gas: `Table::first`
in the SDK, `enroll_many` on fresh slots only, its test. M2, the price's
doc comment contradicting the measurements: re-measured and restated
(above). L1, the claim's expiry boundary untested: a claim at
`expires_ms` enrolls and one at `expires_ms + 1` is refused, the pins say
"until, inclusive". L2, expired invitations never collected: documented in
identity §6 (a `revoke` or a new `invite` replaces them). L3,
`ROOT_MAX_AGE`'s comment: a root also falls out after 64 later roots. L4,
`Ring::record` replacing the newest root at an equal batch time drops a
root a client may have fetched if two batches share a time: as pinned;
batch times are monotone (core model §8.4) but not strictly, which 7.11's
ingress check should keep in mind. L5, test gaps: kernels' surface
asserted equal to `is_kernel_call`; paths queried on the JAM host too;
`invite` of a malformed digest; the ring test's doc says it judges by
`Ring::accepts`. A workflow's `0x402` call (the φ8 page priced in
`units.rs`) is still untested by a workflow. L6, `count()` and `found`
added to identity §6 and pin G.

**Commits:** `04ec0ad9` the call (runtime, agent, wire, shim, tracer, bench,
the serving per precompile); `e44c4c6e` `vos_wire::credentials` and
`vos-credentials` with their tests; `412949dd` the anchoring test's race;
`c45d0bc6` the review's fixes; the counter's schema list; this record and
the pins' numbers.

**Gate** [measured; 12 GiB scope, `nice -n 10`, 8 jobs, other agents' runs
on the machine, load 9–33]: `just check` at `c45d0bc6` green through the
formatting, the docs, the no-std builds, the lints, the core crates and
`test-recair`; the agent crates then run with `--no-fail-fast` (624 passed
in 43 suites) and `test-reads` (7 of 7). Its failures, each run alone:
- `programs_carry_their_schema_first_in_read_only_data`: the counter's new
  `compress` handler, added to its list (12 of 12);
- `anchoring::an_unlisted_leader_hands_off_to_a_listed_replica` (once, under
  load 27): the alert named node 2, and an election moved leadership on to
  node 3 before the anchor; the test now takes any listed replica the
  alert names (6 of 6 alone);
- `leakage::no_hidden_state_is_in_a_proof` (once): the 4-byte needle, φ7's
  low half, met by chance in a proof masked with the OS's randomness (3 of
  3 alone); a 4-byte needle in a proof of megabytes has a chance of
  about its length over 2^32 a run;
- **left open:** `prover::a_leader_change_submits_a_recorded_statement_once`
  fails 3 runs in 5 on the base `ad1ff380` as on this branch, at low load
  too. The new leader's job was read from the record after the `Proven`
  step stripped its witness (`node/host/src/prover.rs`, `attested`), so its
  worker refuses it ("recorded proved whose proof never arrived, its record
  without its witness") instead of proving it again; the test assumes the
  job was read while the record still held the witness. Holding the old
  leader's proof until every replica's worker held the job did not help:
  a follower's backlog stays empty. The node prover's (7.3's) to settle.

**Review (Fable):** merge; L1–L6 folded (L4 handed off)
(`docs/design/research/slice-7/7.9-fable.md`). L1, the handoff test
asserts the alert names a replica whose key the venue lists, not merely
one other than the leader. L2, `RootRefusal::Unknown` retryable by a path
refetch, stated in pin I's ingress checks, 7.11's tests and identity §5's
check 14: an honest member meets it on a replica's lag, a root replaced at
its own batch time, or one pushed out of the ring. L3,
`a_compression_whose_output_the_meter_cannot_pay_waits_unserved`: the
shop's `absorb` workflow keeps its Poseidon2 state in a page only the
agent writes, at φ8, and a sweep with room for the step's own pages but
not the output's ends at the call unserved, then finishes with the state
computed straight, the backends byte-equal; with `units.rs` pricing φ7
instead it fails [measured]. L4 handed off: the quiet native re-measure
of the call's absolute cost (the machine stayed loaded), for the next
quiet `precompile native` run; the price rests on the loaded ratio, which
errs toward over-pricing. L5, `a_kernel_calling_poseidon2_is_refused`, by
name, split from the unknown-id test. L6, the shim's
`checked_poseidon2_compress_block` (`None` for a word at or above p) and
`poseidon2_compress_into` (the call writes the caller's output), the agent
serving through the former instead of its own p check; `Table::first`
treats a scan that frames no row as `None`, as `Iter` does, a row that
does not decode still trapping. Hand-off to 7.12: the ring's 64 entries
bound freshness in a busy space (64 tree-changing batches within
`ROOT_MAX_AGE` make an honest root `Unknown` before `Stale`), so
`PathKeeper`'s refresh period is well under 64 batches' time; written into
pin G, pin L, 7.12 and identity §6. Gates: the touched tests (the shim's,
`derive`'s, the testkit's workflows, credentials, pricing and hosts, 69;
the handoff test), then `just check` [measured; 12 GiB scope, `nice -n 10`,
6 jobs, other builds running]: green through the formatting, the docs,
the no-std builds, the lints, the core crates and `test-recair`; in the
agent crates only `prover::a_leader_change_submits_a_recorded_statement_once`
failed (the known flake, being fixed apart), and the agent crates rerun
with `--no-fail-fast` passed 627 of 627 in 43 suites, `test-reads` 7 of 7.

### The cluster suite's hang: fjall's drop

The hang 7.3 found (a test thread parked on a futex, its nodes' threads
gone) is fjall's: `DatabaseInner::drop` in 3.1.12 sends `Close` to its
workers with a blocking `send` on a queue of 1 000, every 10 µs, until its
worker count reaches zero. On a loaded host the workers take the first
few late, the queue fills, and once the last worker has taken its own
and is leaving, the next `send` blocks for good: nothing takes from the
queue again. Every store close can meet it; caught here in
`vos_checker::spaces::node_key` (a node opened and shut down to learn its
key) under `messages::messages_cross_overlapping_replica_sets`, the
stack fjall's `db.rs:76` in `flume::Sender::send`. Upstream fixed it in
3.1.13 (`f18624f`, a `try_send` that drains first), so the pin moves to
`=3.1.13` (its crate checked equal to the tag; it also skips journal
items already flushed on recovery, makes `remove_weak` weak, and moves
`Openable`; none of which the store uses but the recovery fix).

- **The watch** (`vos_checker::watch`): every `wait_until`, `poll` and
  `install_at_leader`, in every suite, is registered with its bound; the
  cluster harness also watches each node's start and stop, its calls,
  `leader` and the cluster's whole life, by bounds each suite sets
  (`BOUNDS`: the cluster suite 600 s a cluster, 60 s a start or stop,
  and an idle bound of 300 s with no wait pending or moving; the chain
  and carrier suites, whose proofs take minutes, 3 600 s and 1 800 s and
  no idle bound). A wait past its bound plus 180 s of grace, or the idle
  bound, writes every wait pending, the last each thread ended, each
  thread's state and wchan and, where `gdb` can attach (the process sets
  `PR_SET_PTRACER`), every thread's stack, then aborts; in the carrier
  suite that goes to its capture file. `VOS_CHECKER_WATCH=off` turns it
  off, for a test held in a debugger. It is what caught this one: the run
  aborted at 780 s with the stack above instead of hanging. The cluster
  now stops its nodes before its data directories go (they were removed
  first; nothing was seen to fail from it).
- **Tests:** the watch's own two, each the test binary run again alone:
  a wait that never ends aborts naming it, and an idle process aborts
  naming the last wait each thread ended (both hang without the watch,
  failing at the parent's minute). No regression test for fjall's race:
  it needs a worker preempted between taking its `Close` and leaving, and
  a standalone loop of 540 store drops under CPU hogs, one CPU, or a
  flush in flight at drop, never met it.
- **Runs** [measured; two whole suites at once, load 40–90]: 58 suites on
  3.1.12 under `gdb` without the watch, no hang (1 timing failure); 19
  suites with the watch, one hang caught as above (and 1 timing failure);
  40 runs of `snapshots::` and `replication::`, one failure of
  `a_snapshot_stream_outlasting_the_leaders_deadline_goes_on` ("node 2
  started 1 streams past the answered one"), a stream started again past
  an answered one on a starved host, not a hang; left as it is. The two
  timing failures were `liveness::a_restarted_follower_hears_its_quiet_leaders_at_once`
  (10.02 s against 10 s) and
  `liveness::quiet_groups_elect_again_when_their_leaders_node_stops`
  (never quiet within 10 s), both at load near 80.
- **Review (Opus):** folded: the cluster bounds made each suite's (the
  chain and carrier suites share the harness, and their proofs take
  minutes), the cluster's drop stops its nodes without holding their
  ports (a second panic while unwinding), `VOS_CHECKER_WATCH=off` and
  `nostacks` in place of an empty `PATH`, unnamed threads by id.
- **Gates** [measured; 12 GiB scope, `nice -n 10`, 6 jobs]: the watch's
  tests, the chain and carrier suites built, the cluster suite twice
  (116 of 116 each), then `just check` green.

## Step 7.6: the scale runs

From vos-core `84607818`, on `s7/7.6`. Run 1 only; runs 2–6 wait for a
quiet desktop, which the owner schedules.

**The harness, three commits:**
- **Reads at a cut left open by the run's end** are counted apart
  (`not_closed`): a read still `Attesting` when the driver gives up, its
  window closing after the load's last send, is neither answered nor an
  error; the report gives it as "N not closed in the run". Tests: the
  verdict, the counts, the report's line.
- **`down` stopped nothing on a node host.** `systemctl --user stop A B C`
  with one unit not loaded (a node host has no driver unit) stops none of
  them, and the script hid the error: the smoke's nodes and samplers ran
  on for 40 minutes after its report, and the next `check` refused the
  ports. Each unit is now stopped on its own, and the script fails when one
  still runs. Test: a stand-in `systemctl` that refuses as systemd does.
- **Agents are created sixteen at once.** Each creation mostly waits for
  its group's first election, about 2 s: 10,000 idle agents took over five
  hours one at a time, and now 26 minutes (0.15–0.17 s an agent).
  Placements are still drawn in order from the seed.

`cargo test -p vos-scale` green (48), clippy clean.

**Run 1, the per-replica cost** [measured; `~/vos-scale/runs/`
`20261026T211953Z-r1-idle-1k`, `20261026T220041Z-r1-idle-5k`,
`20261026T225257Z-r1-idle-10k`]:
- **The setup:** S35's layout, the three nodes on compumax (Threadripper
  2990WX, cores 0-3, 4-7 and 8-11, `performance`, one Samsung 970 PRO,
  1 GbE wired), the driver and the coordinator on the desktop over Wi-Fi
  (S45, S52: its round trips p50 1.0 ms, p99 2.4 ms). Every agent has three
  replicas on three nodes, so each node holds every agent: `I` idle agents
  are `I` replicas a node.
- **The command:** `vos-scale run --shards 8 --idle I --users 1000
  --rate 10 --secs 2100`, `I` = 1,000, 5,000 and 10,000: the same seed, the
  same light load (10 calls a second, the default mix) and the same
  placements of the shards. The window is the load past its 10 s ramp,
  34.5–34.7 minutes, every agent created before it.
- **The numbers,** per node, the mean of the three (each node within a
  few percent of the others):

| replicas a node | RSS at the window's start | node CPU | `vos-node` thread | its wakes/s | all wakes/s | `late` p50/p99/p99.9 |
|---|---|---|---|---|---|---|
| 1,008 | 307 MiB | 7.4% of a core | 2.9% | 957 | 2,250 | 8 / 192–320 / 1,280–1,536 µs |
| 5,008 | 1,182 MiB | 9.8% | 5.1% | 2,648 | 3,874 | 7 / 192–320 / 1,280–1,536 µs |
| 10,008 | 2,272 MiB | 12.6% | 7.6% | 4,579 | 5,768 | 8 / 192–224 / 1,280 µs |

- **Per 1,000 idle replicas** (the slope from 1,008 to 10,008): **218 MiB
  of RSS**, 0.58% of a core, 0.40 wakes a second a replica on the runtime
  thread. The intercept, a node with no idle agents, is about 87 MiB.
  0 elections and 0 leader changes in all three runs, over 30,024 groups
  at 10k. The load's own numbers did not move with `I`: 21,046 calls
  answered in each run, no error, transfers p99 41 ms, disk 15.6–15.7%
  busy at 0.8 ms an I/O in each.
- **T3** (10^4 agents a space, at most 5% of a core and 64 MiB per 1,000
  replicas): the 10k run is T3's shape, every node holding 10^4 replicas.
  **CPU met** (0.58% of a core per 1,000, nine times under); **RSS missed,
  3.4 times over** (218 MiB per 1,000; 2.2 GiB a node for idle agents).

**The binding resource is memory, and the first suspect binds:**
- **The group inbox, allocated whole at creation.** Each group's inbox is
  `smol::channel::bounded(GROUP_INBOX)`, 1,024 slots
  (`node/host/src/node/directory.rs`), and a bounded `concurrent-queue`
  allocates and stamps every slot when it is made. A slot is the stamp and
  a `group::Input`, 176 bytes [measured, `size_of`], so 184 bytes, and
  1,024 of them are 184 KiB a group: **about 84% of the 218 KiB a replica
  costs**, in a queue an idle group never fills. The rest, about 34 KiB a
  replica, is the group's tasks, its Raft core and its shared state; that
  alone would meet T3 (34 MiB per 1,000).
- **Idle Raft timers wake, but do not bind here.** The runtime thread's
  wakes grow by 0.40 a replica a second, what the code predicts: a
  follower's election deadline fires every 1.5–3 s (pushed out by the pair
  heartbeat once awake), a leader's check-quorum every 3 s, with no
  per-group heartbeats while idle. At 10k they cost the runtime thread
  7.6% of a core against 2.9% at 1k, and its `late` did not move: the
  timers are not what binds at 10^4.
- **A growth with the load, not with `I`:** RSS grew by 136–141 MiB over
  each window, linearly (3.9 MiB a minute, about 6.5 KB a call), the same
  at 1k, 5k and 10k. Not yet attributed; the suspect is the Raft entry
  cache (`cache_bytes`, 16 MiB a group by default, 8 shards here: 128 MiB
  at most), with the accounts' and sessions' rows. Not run long enough to
  see whether it levels.

**What this means for runs 2–6 and the levers:**
- **Run 4 cannot run as built.** 10^5 idle agents are 10^5 replicas a node
  here: at 218 KiB each, 21 GiB a node, past the units' 8 GiB cap and,
  three nodes together, past compumax's 62 GiB. The inbox lever comes
  first: allocate it as it fills (a channel without slots reserved, its
  bound kept by a count), or a much smaller bound. That would bring a
  replica to about 34 KiB, 10^5 to about 3.4 GiB a node.
- **Quiescing idle groups is run 4's second lever.** At 10^5 replicas the
  timers' slope gives about 40,000 wakes a second and about 58% of a core
  on the one runtime thread, which 7.5 already found 81–85% busy under
  load. Run 4 will likely meet it once the inbox is fixed.
- **Runs 2, 3, 5 and 6 (`K` = 64, few idle agents):** the per-replica
  cost is negligible there (64 replicas a node, 14 MiB). The load-driven
  growth matters for T6: if it is the entry cache, 64 shards may hold up
  to 1 GiB a node before it levels, and T6's flat RSS is judged after it.
- **Creating 10^5 agents** at sixteen at once would take about 4.5 hours:
  run 4 wants more creators.
- **Reads at a cut need `--representative`** (below).

**Odd, and recorded:**
- **Every read at a cut failed, in every run, while the load ran:**
  94–98 `Workflow(Attesting)` a run, only 1–5 of them left open by the
  run's end. A read is served once the representative's `Closed` for its
  window applies (7.3, C9), and these runs, as the smoke, had no
  representative: no window ever closes. The smoke's 14 errors were this,
  not the run's end. Runs 2–6 pass `--representative`; the harness could
  refuse a mix with reads at a cut and no representative.
- compumax's clock read 16–34 ms ahead of the desktop's, both synced:
  under `check`'s 100 ms bound, but in every latency that crosses the two.
- The desktop's governor was `powersave` (warned), harmless for run 1:
  the driver used 0.01 cores.
- `owner-decisions.md` has no S53; S35, S36, S45 and S52 were read.

### 7.6: the per-replica cost's levers

From vos-core `b824740c`, on `s7/7.6b`. Run 1 found memory binding, so
the plan's levers came first, each its own commit:

- **`722d6932` The inbox takes memory as it fills.** The group inbox was
  `smol::channel::bounded(1024)`, 184 KiB reserved per group. It is now
  an unbounded channel with its bound kept by its count: an input past
  1,024 is dropped and resent as before, in the same order. Its 31-slot
  blocks are allocated as it fills and freed as it drains, so an idle
  group holds none. Test: the bound drops past it, keeps order, and
  makes room as it drains.
- **`8e0a4fe9` and `a899ef7b` Quiet groups wait on no timer of their own.**
  `Core::quiescent(margin)` says when the core's only deadline is one
  the pair heartbeat stands in for:
  - a follower whose leader was vouched for more than one heartbeat
    interval before its stickiness lapses;
  - a leader that is idle, caught up, and has every member's node heard.

  The driver then records a `Quiet` and waits for a message, a local, or
  a safety round of ten election timeouts. Each pair heartbeat round
  wakes the quiet groups it no longer vouches for: a follower whose
  leader has not listed it within the lower bound, or a leader with a
  member unheard within the upper bound. The woken driver vouches
  before it ticks. `Groups::quiet` counts the quiet groups.

  The Opus review (Raft correctness and liveness) found nothing unsafe.
  Its fixes are folded into `a899ef7b`:
  - A quiet leader with nothing waiting for it (inbox, locals, and its
    leader loop's queue) counts as gone round at each beat. A queued
    input behind a busy runtime then no longer drops it from the listing
    at once, and a wedged runtime with calls queued still does after
    two timeouts.
  - Groups go quiet only while the beat is on time.
  - `Core::resume` makes a leader resumed past its check-quorum count
    only members heard since.
  - `wake_quiet` no longer holds the runs' lock.

  Tests:
  - the core's quiescence and resumption (5);
  - a cluster test: every idle replica is quiet, a call wakes its group
    with no term moving, and the group goes quiet again.

  The liveness suite stays green, including elections when a leader's
  node stops or its writer stalls.
- **`ccf2780f` The stats give what the caches hold:** the store's block
  cache and write buffers, and the groups' Raft entry caches summed,
  recorded each poll in `nodes.jsonl`. This attributed the growth
  (below).
- **`a13f5400` The harness refuses reads at a cut without
  `--representative`.** `run` refuses before it deploys and `drive`
  refuses too, each naming the way out. Test included.

`just check` green.

**Run 1 again** [measured; `~/vos-scale/runs/`
`20261027T064256Z-r1b-idle-1k`, `20261027T072743Z-r1b-idle-10k`]:
- **The setup and command** were run 1's: `--shards 8 --idle I --users
  1000 --rate 10 --secs 2100`, plus `--representative`, which the
  harness now requires for the default mix. That adds one agent, three
  replicas.
- **Binaries.** The 1k run used the binary before the review's fixes
  (`ccf2780f`); the 10k run used `a899ef7b`. The fixes change only
  liveness edges, not idle cost.
- **The table** gives the mean of the three nodes, over the same
  34.8-minute window past the ramp:

| replicas a node | RSS at the window's start | node CPU | `vos-node` thread | its wakes/s | all wakes/s |
|---|---|---|---|---|---|
| 1,009 | 132 MiB (was 307) | 6.7% (7.4%) | 2.2% (2.9%) | 527 (957) | 1,787 (2,250) |
| 10,009 | 542 MiB (was 2,272) | 8.1% (12.6%) | 2.7% (7.6%) | 817 (4,579) | 2,159 (5,768) |

**Per 1,000 idle replicas** (the slope from 1k to 10k), against run 1:

| | before | after |
|---|---|---|
| RSS | 218 MiB | 45.6 MiB |
| node CPU | 0.58% of a core | 0.16% |
| runtime-thread wakes per replica a second | 0.40 | 0.032 |
| runtime thread's CPU | | 0.05% of a core |

- **T3 met on both counts:** 45.6 MiB against 64 MiB, and 0.16% of a
  core against 5%.
- The intercept is unchanged at about 86 MiB.
- Every replica was quiet at both sizes: 10,008–10,009 of 10,009.
- 0 elections and 0 leader changes.
- The load's numbers held: 21,046 calls answered, no errors, transfer
  p99 within run 1's.
- **Reads at a cut now succeed:** all 99 in each run, p50 164 ms, p99
  459 ms from the window's close. Run 1 failed all of them.
- **What the remaining wakes are:**
  - The runtime thread's 0.032 wakes per replica a second are the safety
    round, one every 30 s.
  - At 10^5 replicas they project to about 3,200 a second, against
    40,000 before.
  - Lengthening the safety round is the lever if run 4 needs it.
  - The pair heartbeat's thread (`vos-liveness`) took 0.9% of a core at
    10k for its listing and quiet scan, both O(groups) per beat. That
    thread is the next to watch at 10^5.
- **Expected at 10^5:** the slope puts 10^5 replicas at about 4.6 GiB a
  node. That is within an 8 GiB unit, but three such nodes do not fit
  compumax's 62 GiB beside its reserve. Run 4 needs higher caps or fewer
  replicas a node.

**The growth under load is the store's memtables, not the Raft entry
cache:**
- **RSS still grew 4.1 MiB a minute** at both sizes, as in run 1.
- **The write buffers account for nearly all of it:**
  - At 1k, fjall's write buffers grew from 4.6 to 126 MiB in the window
    (3.5 MiB a minute), against RSS's 141 MiB.
  - At 10k, they grew from 37 to 155 MiB, 3.5 MiB a minute, until minute
    33.8. A memtable of about 64 MiB then flushed and the buffers fell
    to 91 MiB.
- **The Raft entry caches stayed flat:** 1.2–2.6 MB a node at 1k and
  11–12 MB at 10k. The block cache stayed under 1 MB.
- **So no bound changes here.** The entry cache is not what grows. Each
  keyspace's memtable is already bounded at fjall's 64 MiB, four
  keyspaces, and flushes there, as the 10k run shows. Fjall 3.1.13's
  total write-buffer cap (`max_write_buffer_size`) is accepted but not
  enforced.
- **Why it rises at this load:** at 10 calls a second the memtables take
  over half an hour to fill, so the growth looks unbounded within a
  35-minute run. At T1's rate they fill and flush in seconds.
- **The plateau** is about 256 MiB of active memtables a node, plus
  those being flushed.
- **The trade-off:** smaller memtables would lower the plateau at the
  cost of more flushes and compaction at T1, the load already at risk.
  Left for run 2's measurement. T6's soak should judge RSS after the
  memtables' first full cycle.

**Left:**
- The safety round's length, if run 4's wakes bind.
- The O(groups) beat at 10^5.
- The node caps that run 4 needs.
- The memtable plateau, judged at T1 in runs 2 and 6.

### 7.6: runs 2–6 on the LAN

From vos-core `920103b3` (the levers above included), on `s7/7.6c`. The
node binary (`~/vos-scale/bins-7.6c/vos`, copied from vos-core's build) is
the same in every run; `vos-scale` is this branch's.

**The setup:**
- S35's layout: three nodes on compumax, cores 0-3, 4-7 and 8-11, one
  Samsung 970 PRO shared by all three, 8 GiB caps (12 GiB for run 4's
  10^5 step).
- The driver on `sigma`, wired, cores 0-7, `performance`. Its round
  trips to compumax were p50 0.4 ms and p99 0.4–0.6 ms; the desktop
  only coordinated.
- **compumax's governor:** `performance` for runs 2–4 at 10^4
  (2026-10-27), `ondemand` for run 4 at 10^5 and runs 5–6 (2026-10-30,
  warned by every `check`; the harness changes nothing on the hosts).
  Under load the nodes' cores ran at the same 76% of their top clock in
  both, so the runs compare, but S53's setting was not in force for the
  later three.
- Clock offsets were 1–10 ms in every `check`, all hosts synced.
- Every run: `L` = 2 min, `--representative`, `--identity` (a row a user,
  written 10 times a second), the default mix, `K` = 64, a full deploy.
- The window is the load past a 10 s ramp; the 30-minute and longer runs
  were reported again with `--ramp-s 60` (`report-ramp60.txt` in each).

**The harness, five commits:**
- **`c85ba9f6` T5's fault.** `--kill NODE --kill-at-s --restart-at-s` on
  `run` and `drive` kills a node's unit (SIGKILL) under load and starts
  it again on its data, the instants in the run's `faults.json`. Test:
  the kill waits for the unit to go, and fails when it outlives the kill.
- **`b54ae465` The identity agent's install read again.** One replica
  answers the install; the one the rows go through may apply it later,
  and run 2's first 2,000-a-second step failed with "the identity agent
  has nothing installed". Test: the read retries until it finds the
  schema, and times out.
- **`35f28f52` `--creators`**, the agents created at once (16 by
  default). At 64, creation ran at 9–10 agents a second, against 6 at
  16: 10^4 in 18 minutes, 10^5 in 2.8 hours. The node, not the harness,
  bounds it past that.
- **`8ee4fa5e` The driver reads its agents over kept connections.** It
  read each agent's record over a connection of its own, one socket in
  `TIME_WAIT` a read; with 10^5 idle agents for the readers, sigma ran
  out of local ports ("Address not available") and run 4's first 10^5
  attempt ended after its 2.8 hours of creation. Test: 64 agents over at
  most 16 connections (64 before).
- **`aca79db2` `harness.start_s`**, how long a node may take to answer
  once started (90 s by default). A node opens every group it replicates
  first: 3.5 minutes at 10^5.

`cargo test -p vos-scale` green (52, its log ending `exit=0`), clippy
clean.

**Run 2, the baseline** (`U` = 10^5, 8-minute steps, then 30 minutes at
T1's rate). Rates are all calls a second; transfers are 80% of them.
Latencies are the transfers', in ms. Node figures are the mean of the
three; commit is the worst node's.

`x` = 98%:

| offered | transfers offered, answered/s | p50 / p99 / p99.9 | errors | node cores (of 4) | `vos-node` thread | commit p50 / p99 | runtime `late` p99 | disk ms/io | driver late, worst |
|---|---|---|---|---|---|---|---|---|---|
| 1,000 | 800, 800 | 98 / 229 / 328 | 0 | 1.77 | 64% | 25 / 49 | 20.5 | 1.0 | 2.0 ms |
| 1,500 | 1,200, 1,200 | 98 / 328 / 459 | 0 | 1.89 | 62% | 25 / 57 | 20.5 | 1.3 | 1.9 ms |
| 2,000 | 1,600, 1,599 | 115 / 328 / 524 | 0 | 1.98 | 61% | 25 / 82 | 20.5 | 1.6 | 2.1 ms |
| 3,000 | 2,403, 2,403 | 115 / 459 / 655 | 0 | 2.13 | 54% | 29 / 98 | 16.4 | 2.0 | 2.4 ms |
| 4,000 | 3,196, 3,197 | 131 / 524 / 918 | 0 | 2.30 | 50% | 33 / 131 | 16.4 | 3.5 | 2.3 ms |
| 5,000 | 3,999, 3,999 | 164 / 655 / 1,311 | 0 | 2.45 | 46% | 33 / 164 | 20.5 | 4.4 | 2.1 ms |
| 5,000, 30 min | 4,001, 4,001 | 164 / 786 / 1,311 | 0 | 2.51 | 48% | 33 / 197 | 20.5 | 5.6 | 2.8 ms |
| 6,500 | 5,199, 5,190 | 229 / 1,573 / 2,621 | 0 | 2.73 | 43% | 41 / 229 | 24.6 | 6.1 | 2.4 ms |
| 8,000 | 6,402, 6,371 | 393 / 4,194 / 7,340 | 0 | 2.93 | 39% | 49 / 328 | 28.7 | 9.3 | 2.8 ms |
| 10,000 | 8,003, 7,173 | 10,486 / 100,663 / 117,441 | 0 | 3.04 | 36% | 57 / 393 | 24.6 | 9.3 | 3.1 ms |

`x` = 30%:

| offered | transfers offered, answered/s | p50 / p99 / p99.9 | errors | node cores | `vos-node` | commit p50 / p99 | `late` p99 | disk ms/io | driver late |
|---|---|---|---|---|---|---|---|---|---|
| 5,000 | 4,001, 4,001 | 131 / 655 / 1,049 | 0 | 2.27 | 46% | 33 / 131 | 16.4 | 4.7 | 1.8 ms |
| 5,000, 30 min | 4,001, 4,002 | 131 / 655 / 1,049 | 0 | 2.33 | 47% | 33 / 164 | 16.4 | 4.5 | 3.1 ms |
| 8,000 | 6,401, 6,388 | 229 / 1,835 / 3,146 | 0 | 2.75 | 40% | 49 / 262 | 20.5 | 6.3 | 2.3 ms |
| 10,000 | 8,002, 7,879 | 786 / 25,166 / 33,554 | 0 | 2.92 | 36% | 49 / 328 | 20.5 | 7.7 | 2.8 ms |
| 12,000 | 9,607, 8,162 | 2,621 / 201,327 / 234,881 | 0 | 2.96 | 35% | 57 / 328 | 20.5 | 8.6 | 2.5 ms |

- **The knee,** one host's (S35): at `x` = 98% the nodes keep up through
  8,000 a second, p99 oscillating 1–7 s with no trend. At 10,000 they
  answer about 7,200 transfers a second against 8,000 offered, and the
  backlog grows. **The knee is about 8,000–9,000 a second.** At `x` = 30%
  it is about 10,000: transfers are answered at offer there, but p99
  climbs through the run, and 12,000 is past it. The cross share costs
  little: at 5,000, p99 786 against 655 ms.
- **No p99 within 50 ms at any rate:** 229 ms at 1,000 a second.
- 0 errors, 0 elections and 0 leader changes in every step. The driver
  was never late (at worst 3.1 ms, 0.00% of sends past 10 ms) and used
  at most 0.39 cores. The driver did not bind.
- **The rerun without the slowest host is not measurable** (S35): three
  node hosts on one machine. Each report names a "slowest" node (c1, c2
  or c3, by commit p99), but the three share one disk, NIC and CPU.
- **The model at `U` = 10^5:** past 5,000 a second each active user makes
  `r` = rate / 5,000 calls a second, one at a time. At 8,000, half the
  transfers waited behind their own user's previous call (`queued`).
  Part of the latency past the knee is that serialisation, not the nodes.
- The report's "binding" column says "disk 70%" at most rates. That is
  the NVMe's `%util`, which counts any I/O in flight and saturates long
  before the device does. Read it as the fsync latency below, not as a
  full disk. At 10,000 a second the column reads CPU 75%.

**Where a transfer's time goes**, at 5,000 a second, 30 minutes, node 1
(means from `nodes.jsonl`, in ms):
- **queued 63:** waiting for the agent's next batch. A group has one batch
  in flight, so this is about one batch's length.
- **batch 103:** refine start to apply. Of it:
  - commit 45 (p99 197);
  - commit to apply here 37 (p99 164);
  - refine 2.1;
  - dry run 0.9;
  - the executor queues 1.8 and 3.7;
  - propose 1.1.
- **batch inputs:** 19 a batch.
- **The writer's fsync** (`flush_synced`) 21 ms mean, p99 82, 46 a second
  a node, on the disk all three nodes share. Disk writes ran at 51 MB/s.
- **CPU:**
  - the runtime thread 48% of a core, its `late` p99 20 ms;
  - three executors at 45% each, `vos-storage` 34%;
  - 2.5 of the node's 4 cores;
  - 1,400–7,400 preemptions a second (the node runs more busy threads
    than its 4 cores).
- **At 10,000 a second:**
  - the executors reach 60–63% each;
  - the node uses 3.0 of its 4 cores;
  - the disk's ms per I/O reaches 9.3;
  - the runtime thread stays at 36%.

  The knee is the 4-core cpuset and the shared disk's fsync, together.

**Run 3, users** (`U` = 10^6, `x` = 98%, 30 minutes each; runs
`20261027T180915Z-r3-u1m-5000`, `20261027T184355Z-r3-u1m-6400`):

| offered | transfers answered/s | p50 / p99 / p99.9 | errors | users, sessions | node cores | commit p50 / p99 | fsync mean / p99 | disk MB/s, ms/io | `late` p99 |
|---|---|---|---|---|---|---|---|---|---|
| 5,000 (T1) | 3,989 | 393 / 10,486 / 25,166 | 223 timed out | 231,384, 231,601 | 2.61 | 57 / 393 | 35 / 262 | 78, 16.4 | 41 |
| 6,400 (80% of 8,000) | 3,652 | 41,943 / 536,871 / 671,089 | 1,479,494 (all but 39 timed out) | 233,052, 1,678,470 | 2.57 | 57 / 393 | | 16.0 | 57 |

- **At T1's rate it holds, barely.** It answered at offer, but p99 rose
  from about 1 s in the first 15 minutes to 10–21 s in the last.
- **At 6,400 it collapsed.** Transfers were answered at 3,600–4,000 a
  second, timeouts began at minute 9, and the run was lost. Sessions
  re-opened after timeouts reached 1.68 million. **At 10^6 users the knee
  is about 5,000 a second, not 8,000.**
- **What changed from 10^5 users at the same rate:**
  - 231,000 distinct users and accounts written in the run, against 23,000;
  - disk writes 78 against 51 MB/s;
  - the fsync mean 35 against 21 ms, its p99 262 against 82;
  - batches twice as large (37 inputs) and twice as long (207 ms);
  - CPU and the runtime thread barely moved.

  **The binding resource at T1's shape is the shared disk:** the store's
  write traffic as the state grows, and the fsync each commit waits on.
- 0 elections and 0 leader changes; no session refused.

**Run 4, agents** (`U` = 10^5, 5,000 a second, `x` = 98%, readers 1%,
`--creators 64`):

| `I` | replicas a node | RSS, all quiet, before load | under load | transfers p50 / p99 / p99.9 | errors | reader reads, p99 from close |
|---|---|---|---|---|---|---|
| 64 (run 2's 30 min) | 66 | | 1,830 MiB | 164 / 786 / 1,311 | 0 | |
| 10^4 | 10,066 | | 2,294 MiB | 164 / 918 / 1,311 | 0 | 1,560 of 1,560, 1.8 s |
| 10^5 | 100,066 | 4,330–4,440 MiB | to the 12 GiB cap in 10.5 min, two nodes OOM-killed | p50 / p99: 131 / 393 in the first 10 s, 524 / 2,621 at 2 min, 16,777 / 58,720 at 5 min | timeouts from minute 10; the driver OOM-killed at its 8 GiB | |

- **10^4:** the idle replicas cost 464 MiB, **46 MiB per 1,000**, run 1b's
  slope. They cost no measurable CPU under load. Every replica was quiet
  once idle; 0 elections.
- **10^5, idle:** every replica quiet (100,064–100,066 of 100,066).
  - **4.33 GiB a node: about 43 MiB per 1,000** replicas past the
    86 MiB intercept.
  - **0.17–0.29 of a core a node** while the driver read the agents'
    records before its load, at most 0.29% of a core per 1,000.
  - `vos-liveness`, the pair heartbeat's O(groups) listing and quiet scan,
    took 12.5–12.9% of a core, against 0.9% at 10^4: fourteen times for
    ten times the groups.
- **10^5, under the baseline load:** the nodes could not hold it.
  - In the first minute transfers p99 went from 393 ms to 2.6 s.
  - Quiet groups woke (quiet fell from 100,066 to 83,000–91,000) and
    elected: node 1's summed terms rose from 109,000 to 1.24 million in
    ten minutes. Node 2 counted 1.45 million elections.
  - Commit p99 reached 3.1 s and queued p99 5.2 s.
  - RSS grew about 1 GiB a minute, from 4.5 GiB to the 12 GiB cap.
  - c3 and c1 were OOM-killed 10.5 minutes into the load, and c2 stopped
    answering.
  - The driver's unanswered calls (44,000 in flight) took it to its own
    8 GiB cap and OOM.
  - Run `20261030T113939Z-r4-idle-100k-c`.
- **Why not higher caps:** compumax fits three 18 GiB caps at most
  (3 × 18 + 2 within its 57 GiB free). Memory was not the cause: the
  latency diverged and the elections began in the first minute, at
  4.5 GiB. More memory would only delay the OOM by minutes.
- **A cold restart at 10^5 does not converge either**
  (`20261030T111501Z-r4-idle-100k-b`, the agents of the first attempt
  started again on their data):
  - Each node took 3.5 minutes to answer.
  - Twenty minutes later only 6,468 of the 100,066 groups had a leader.
  - The nodes' summed terms rose by about 120,000 a second, on 1.4 cores
    a node.
  - The shards' calls were refused `NotLeader`, then timed out. The run
    was stopped.

**Run 5, faults, T5-partial** (S36: run 3's shape, `U` = 10^6, 5,000 a
second; c2's unit SIGKILLed at 600 s and started again at 900 s; polls
and intervals every second, `every_s` = 1; run
`20261030T143927Z-r5-fault-c2`):

| | measured | T5's bound |
|---|---|---|
| agents c2 led at the kill | 21 of 65 | |
| each led again elsewhere | 2.2–4.9 s after the kill (p50 2.9 s; the polls' 1 s grain) | 5 s: **met** |
| throughput (all kinds, answered a second) | 5,031 before; 3,000–4,100 (60–80%) for 30 s; 4,700–5,900 from 31 s | 80% within 30 s: **missed by about a second** |
| the node answering after its restart | 7.1 s, its statuses at 7.4 s | 60 s: **met** |
| its replicas caught up (within 20 entries of the leaders) | 163 s after the restart, from 1,900 entries behind | |
| elections, leader changes | 69, 22 | |

- **The throughput gap** is the calls in flight to c2: they timed out at
  the driver's 30 s bound (23,000 in the two seconds at 30–31 s), and a
  user's next call waits behind its last. Everything else moved within
  5 s.
- **The restart costs more than the kill.**
  - For 40 s after it, queries routed to the catching-up follower were
    refused `Behind` (up to 10,000 a second).
  - Answered calls fell to 1,900–3,300 a second while c2 replayed its
    1,900 entries a group.
- **The run did not settle again.** At T1's shape the system was at its
  knee (run 3), and two of three replicas commit at their slower one.
  Transfers p99 rose from 786 ms before the kill to 25 s in the next
  minute, and to 400 s by the end. 839,000 calls timed out over the run.

**Run 6, soak** (run 3's shape for 2 hours; run
`20261030T151526Z-r6-soak`). Transfers per 10 minutes:

| minutes | answered/s | errors | p99 (median interval) | RSS c1 / c2 / c3, MiB |
|---|---|---|---|---|
| 0–10 | 3,991 | 0 | 1,048 ms | 1,972 / 1,964 / 1,970 at 10 |
| 10–30 | 3,998–4,007 | 0 | 1,835 ms | 2,033 / 2,015 / 2,055 at 30 |
| 30–40 | 3,014 | 203,638 | 67 s | |
| 40–60 | 2,623–2,645 | 543,000–668,000 | 336–537 s | 1,960 / 1,965 / 1,990 at 60 |
| 60–90 | 1,642–2,156 | 822,000–1,190,000 | 11–18 min | 2,088 / 2,082 / 2,053 at 90 |
| 90–120 | 1,387–1,651 | 1,241,000–1,302,000 | 22–36 min | 2,245 / 2,270 / 2,227 at 120 |

- **It held T1's rate for 30 minutes, then collapsed.** 9.5 million
  calls timed out in all. 551,861 distinct users opened 9.95 million
  sessions (a timed-out call's user starts another), 162,009 at the
  busiest shard.
- **What bound after minute 30 was the runtime thread, not the disk:**

  | node 1, minutes | `vos-node` | `late` p99 | `prepare` mean (the batch's state read, on the runtime thread) | `resume` mean | fsync mean | disk writes a second |
  |---|---|---|---|---|---|---|
  | 1–25 | 45% | 41 ms | 0.36 ms | 5.4 ms | 34 ms | 2,029 |
  | 40–60 | 76% | 115 ms | 0.93 ms | 20 ms | 27 ms | 1,660 |
  | 100–120 | 87% | 262 ms | 6.4 ms | 43 ms | 25 ms | 1,199 |

  As the accounts and the sessions grew, each batch's synchronous state
  read on the runtime thread grew eighteenfold. The leader loops' wait to
  be polled (`resume`) followed it, while the disk did less.
- **The memory:**
  - RSS rose 10–13% from minute 30 to minute 120, ranging 1,960–2,270
    MiB.
  - The block cache sat at its 1 GiB cap from minute 15, and the write
    buffers stayed at 105–145 MiB.
  - The Raft entry caches moved between 167 and 283 MiB.
  - 0 elections, 0 leader changes.

**The memory under load:**
- The store's block cache fills to its 1 GiB cap within 15–30 minutes of
  load; that is most of the RSS growth.
- The write buffers cycle, their plateau about 130 MiB.
- The Raft entry caches held 74–283 MiB.
- A node at T1's shape settles near 2.0–2.3 GiB, plus 43–46 MiB per 1,000
  idle replicas.

**The targets:**
- **T1 missed.**
  - At 10^6 users and 5,000 a second (`x` = 98%), p99 was 10.5 s against
    50 ms over 30 minutes (run 3), and 223 calls timed out.
  - The same load collapsed after 30 minutes in run 6.
  - No session was refused.
  - Even at 10^5 users, p99 was 786 ms.
  - The binding resources: one batch in flight a group, the one disk's
    fsync and write traffic, and, as the state grows, the batch's state
    read on the runtime thread.
- **T2 not measurable** (S35). One host's knee is about 8,000–9,000 a
  second at 10^5 users and about 5,000 at 10^6, against T2's 40,000.
- **T3 met at 10^4.** 46 MiB and 0.16% of a core per 1,000 replicas.
- **T3's 10^5 stretch: idle cost met, the node at 10^5 under load
  missed.**
  - Idle, 43 MiB and at most 0.29% of a core per 1,000.
  - Under the baseline load, quiet groups lost their leaders, elections
    ran away, and memory grew to the cap (above).
  - A cold restart at 10^5 never re-elected.
- **T4 met where measured.**
  - Every read at a cut was served in run 2's 30-minute runs (46,652 and
    46,368, p99 2.1 s from the close) and in run 4 at 10^4 (46,399, p99
    2.6 s).
  - In run 4, 1,560 of 1,560 readers' reads were served, p99 1.8 s from
    the close, against `B_w + D + 10 s`.
  - None was `NotClosed`.
  - At 10^6 users, reads timed out with the calls: 1 of 47,005 in run 3,
    and 19,941 of 117,007 in run 6.
  - The representative's work per reader was not separated.
  - C9's fail rate at the LAN's 1–10 ms skew was 0 of 139,467 reads in
    the runs that kept up.
- **T5-partial: mostly met, missed on throughput by about a second.**
  - Re-election in at most 4.9 s (5 s bound), met.
  - Throughput back to 80% at 31 s (30 s bound), missed.
  - The node rejoined, answering, in 7.1 s (60 s bound), met. It caught
    up in 163 s.
  - The load never returned to its pre-kill latency.
- **T6 missed.**
  - RSS after the first 30 minutes rose 10–13%, against within 10%:
    missed by a hair, the block cache already full.
  - p99 was 67 s to 36 minutes after the first half hour, against
    1.0–1.8 s in it. Within 20% was the bound: missed, the throughput
    collapsing at minute 30.
  - The accounts kept growing through the run (551,861 users by its end).

**The levers, by measured effect:**
1. **Batch pipelining**, more than one batch in flight a group. Queued
   (63 ms) is about one batch, so pipelining removes about a third of a
   transfer's time at 5,000 a second. That is the largest share not
   spent on the disk.
2. **Per-batch reads off the runtime thread.** In run 6 the batch's state
   read (`prepare`) grew from 0.36 to 6.4 ms as the state grew, and took
   the runtime thread from 45% to 87% with its `late` p99 at 262 ms. That
   is the soak's collapse. At 30 minutes the runtime thread was not yet
   binding: it ran at 36–64% in runs 2–3.
3. **Quiet groups' liveness at 10^5 under load and on a cold start.** The
   pair heartbeat's O(groups) beat took 12.7% of a core idle. Under load
   the quiet groups lost their leaders and elected without end, and a
   restart never converged. The levers:
   - stagger and rate-limit elections, so a woken or restarted node does
     not campaign for every group at once;
   - keep a quiet group's lease through a busy runtime;
   - shard the liveness scan.

   This needs its own run at 10^5 before T3's stretch can be judged.
4. **The commit-to-apply gap** (37 ms mean at 5,000 a second, 65 ms at
   10^6 users). It sits after the commit, on the latency path, and is
   not fsync.
5. **The fsync's cost on a shared disk.** At 10^6 users, fsync's p99 is
   262 ms, and the store writes about 16 KB per call across the three
   nodes. Write amplification needs measuring (memtable size,
   compaction) before a lever is chosen. On more hosts each node has
   its own disk; T1 and T2 should be re-measured there before this is
   judged a node defect.
6. **The executors and the 4-core cpuset** bind at the knee (3.0 of 4
   cores, 60% each). Batch signature verification is the CPU lever.
   `verify` is 0.09 ms a call, about 0.45 of a core at 5,000 a second.
7. **Not a node lever, but it shapes runs 5 and 6:** the driver starts a
   new session for each timed-out call's user (9.95 million sessions for
   551,861 users in run 6). Once calls time out, the state and the load
   grow with the timeouts. Whether a client should resume its session
   instead is for the client's design, and the model should state its
   choice.

**Left:**
- T2 and the run without the slowest host need four node hosts (S35).
- T5's host kill needs a second node machine (S36).
- T3's 10^5 stretch waits on lever 3.
- T1 and T6 wait on levers 1, 2 and 5; each lever is a commit with its
  before and after against these runs.
- Run 4 at 10^5 and runs 5–6 ran at `ondemand` (above); rerun them at
  `performance` when the levers land.

**The runs**, under `~/vos-scale/runs/`:
- **Run 2:**
  - the smoke: `20261027T142927Z-s76c-smoke`;
  - 98%, 1,000 to 3,000 a second: `20261027T143502Z-r2-x98-1000`,
    `…151411Z-r2-x98-1500`, `…145251Z-r2-x98-2000` (`…144544Z` is the
    attempt the identity race failed), `…150332Z-r2-x98-3000`;
  - 98%, 4,000 a second and up: `…152509Z-r2-x98-4000`,
    `…153549Z-r2-x98-5000`, `…154629Z-r2-x98-6500`,
    `…155712Z-r2-x98-8000`, `…160753Z-r2-x98-10000`;
  - 98%, 30 minutes: `…170345Z-r2-x98-5000-steady`;
  - 30%: `…161903Z-r2-x30-5000`, `…162943Z-r2-x30-8000`,
    `…164023Z-r2-x30-10000`, `…165103Z-r2-x30-12000`;
  - 30%, 30 minutes: `…173625Z-r2-x30-5000-steady`.
- **Run 3:** `20261027T180915Z-r3-u1m-5000`, `…184355Z-r3-u1m-6400`.
- **Run 4:**
  - `20261027T192015Z-r4-idle-10k`;
  - `20261027T200856Z-r4-idle-100k`, stopped by the quota;
  - `20261030T075946Z-r4-idle-100k`, the driver's ports;
  - `20261030T111501Z-r4-idle-100k-b`, the cold restart;
  - `20261030T113939Z-r4-idle-100k-c`, the run under load.
- **Runs 5 and 6:** `20261030T143927Z-r5-fault-c2`,
  `20261030T151526Z-r6-soak`.
- **The inventories** `inventory.toml`, `inventory.r4-12g.toml` (12 GiB
  caps, `start_s` = 1800) and `inventory.r5.toml` (`every_s` = 1) are in
  `~/vos-scale`.
- **The scripts:** those that ran the steps and summarise a run
  (`step.sh`, `r56.sh`, `row.py`, `md.py`, `stages.py`,
  `intervals.py`) are in `~/vos-scale/s76c/`.

## Step 7.10: the credential AIR

Branch `s7/7.10`, from vos-core `84607818`.

**Built:**
- **The tagged `p2` row** (`vos_pvm_recair_air::p2::P2Mode::Tagged`,
  `gadgets::tagged`): `C(T(name), x)`, a constant block on the left of a
  wire pair, which no single mode forms (a wire enters the right half only
  as a node's message beside the row above, or as `act·m` with zeros or
  `prev` on the left). The row sets leaf start's and node's selectors to 1
  and channel first's to −1, `act` zero, its bit a use of the zero wire:
  the input constraint, linear in the preprocessed selectors, reads
  `[c + b·(m − prev), m + b·(prev − m)]`, and `b = 0` by the relation, so
  `[c, m]` with `prev` cancelled. **No AIR change:** no column, constraint
  or degree; the wrap's, the leaves' and the folds' preprocessed columns
  unchanged (`selectors()` is the old one-hot for every other mode). The
  wiring check reads a tagged row's whole message and refuses a free one.
- **Circuits without `h8`** (`Context::finalize_without_h8`,
  `Circuit::check_wiring_without_h8`, `MainTrace::interaction_without_h8`):
  `h8`'s padding rows use the zero wire, so a two-component set must have
  no `h8` row at all.
- **The circuits** (`vos_pvm_recair::credential::circuit`), each one
  wiring whatever its witness: auth (member, leaf, 32 node rows on
  boolean bits, the root out; the nullifier's key, then `scope` absorbed
  by a channel-first row, the nullifier out), 36 permutations; owner, 1;
  membership and payment, 37 (measured, no kind). Every output a public
  word, one M31 a word (`kind` the zero or the one wire's lane), `binding`
  read by no row. Each component at 2^11 rows, the masking's floor.
- **The set** (`vos_pvm_recair_air::masked::CredentialComponents`, a file
  of its own): `p2` and `qm31` masked, after the test's `P2Only`.
- **A one-component masked set refused** (`masked::blinds_its_sums`): one
  blinded component's sum is the logup total's less the public ones', so
  the masked prover and the masked verifier refuse it (before any other
  check); `P2Only`'s test is now that refusal.
- **The Blake2s-M31 stack in `pcs.rs`:** `PcsStack` for the fork's
  `Blake2sM31MerkleChannel`, its `StarkProofAny`, `Commitment` (tagged by
  the stack; a root word ≥ p refused) and `ChannelRef` variants, appended,
  so existing encodings are unchanged.
- **Format 42** registered and admitted, counted on its masked shape
  (`CREDENTIAL_REFERENCE`, derived from the built set by a test): 106 / 62
  (62.93), the query term binding, affine batching (the fork's Blake2s-M31
  path takes it); `h = 512`. **44** (`CREDENTIAL_PROOF_44`, 47 queries, PoW
  16) counted beside it, 110 / 62 (62.92), not registered. **30** retired.
- **The prover and the verifier:** `credential::prove` (the witness checked
  first: a word ≥ p or an unsatisfied piece is `ProveError::Witness`),
  generic `prove_on` / `verify_on` over any channel and format;
  `vos_pvm_final_verifier::credential` (format 42 pinned: configuration,
  pins, log sizes `[11, 11]`, tree widths `[50, 341, 32, 20]`, 467 DEEP
  values; each kind's preprocessed root and program id, the circuit hash of
  format 42, its parameters, `[11, 11, 0]` and the root), `verify(kind,
  words, proof)` picking the circuit by kind; the bytes (postcard,
  canonical, at most 512 KiB) under `credential-bytes`, a feature the
  verifier kit drops (the kit's lockfile has no postcard).
- **The timing example** (`recair/examples/credential_timing.rs`).

**Tests** (`recair/tests/credential`, 19; and the mode gates):
- **Against `vos_wire::credentials`:** every `p2` row's 16 input words the
  reference's compression in order (member, leaf, each node on the side its
  bit picks, the key, the nullifier) at slots 0, `u32::MAX`, `0x8000_0001`
  and random, the root the reference tree's, `Path::proves` on the path;
  the outputs the statement's words; the owner and joint circuits likewise
  (37 and 36 permutations counted); the wiring the blank statement's for
  any witness and slot; a witness the reference refuses refused by the
  circuit by piece (`path`, `nullifier`, `owner`).
- **Proving:** auth and owner proved under 42 and verified by the final
  verifier, from the proof and from its bytes (a trailing or missing byte,
  an oversized buffer refused); the pinned roots and program ids the
  circuits'; two slots one shape; the joint circuit and auth under 44
  verified, a 44 proof refused under 42; the prover on plain Blake2s, a
  tampered sample refused; the reference shape the built set's.
- **Soundness** (each a constraint-satisfying proof of an unsatisfied
  statement, refused by the logup total): a sibling changed, the slot's
  bit 20 flipped, a nullifier of another secret, an owner digest of
  another secret; an honest proof under a changed binding word (the
  interaction PoW or the logup), a changed root, scope or nullifier word,
  the other kind (`PublicWords`), the other kind's root (`Circuit`), a
  relabelled format (`Format`).
- **Forgery:** a prover that skips the leaf's tag (`C(0, m)`, its path's
  root stated): its own circuit verifies under its own root and is refused
  as `Circuit` against auth's; its witness under the pinned circuit refused
  by the prover and, forced, `OodsNotMatching`. A prover that skips the
  path's bits (level 0's selector 2, a blend of both orders, its root
  stated): with the bit's row balanced, refused by the prover and, forced,
  `OodsNotMatching`; unbalanced, `Logup`. A tagged row with `b = 1`, its
  input the node rule's so its constraints hold: `Logup` (the review's L1).
  The mode gates cover the tagged row (honest, and as and against every
  other mode's rule).
- **One-component set:** refused by the prover (`Masking`) and by the
  verifier (`Shape`), before any other check.
- **Leakage** (`leakage.rs`; the pair one member's leaf at two slots of one
  tree, equal public words): 2 and 3 at N = 500 under `heavy-gates`
  [measured]: indistinguishability 19,984 hypotheses, smallest p 6.2e-7
  against a threshold of 1.25e-8; uniformity 19,987, smallest p 6.6e-5;
  none refused (354 s). 4 (the secret, the nullifier's key, the member, its
  leaf and every occupied sibling, two words of one among a proof's
  published values; a planted control found), 5 (two proofs of one witness,
  and of the two witnesses from one seed, share no opening) and 7 (one
  layout).

**x86 timings against the targets** [measured; `credential_timing`, 4
threads pinned to cores 1, 3, 6, 8, `RAYON_NUM_THREADS=4`, median of 15
after 2 warm-ups, quiet (load 2–2.5), two runs]:

| statement | target | prove, median | least | verify | bytes |
|---|---|---|---|---|---|
| auth, 42 | ≤ 60 ms | **74–85 ms (missed)** | 64 ms | 1.9–2.1 ms | 201–205 KB |
| owner, 42 | ≤ 30 ms | **74–84 ms (missed)** | 72 ms | 1.9–2.1 ms | 200–203 KB |
| membership and payment, 42 | ≤ 60 ms | **84–86 ms (missed)** | 47 ms | 2.1–2.2 ms | |
| auth, 44 | (≤ 60 ms) | 40–47 ms | 38 ms | 1.9–2.1 ms | |

- **The breakdown:** the PoW-20 grind alone takes 37–43 ms on average on
  the same 4 threads (12–81 ms, geometric), about half the proof; R1
  3.4–4.0 ms; the rest, about 35–40 ms, is the masked prove of two
  components at 2^11 rows (columns at 2^12, the composition at 2^13, every
  tree at the lifting height 2^15). PoW 16 (format 44) grinds 4–5 ms, so
  auth under 44 proves in 40–47 ms, inside 60.
- **Owner costs what auth does:** the shape is the floor's, not the
  statement's. One permutation or 37, each component pads to `4h = 2^11`
  rows, so the cells, the trees and the grind are the same; the target of
  30 ms is out of reach at this format whatever the circuit (at 44 it
  would be about 40 ms too).
- Verification 1.9–2.2 ms on 4 threads, under pin I's 10 ms on one core
  (not measured on one core here). Under load (other agents' runs, load
  20–60) the same cells took 98–440 ms (`timing1`–`timing3` runs); 8
  threads across the P- and E-cores were slower (auth 100 ms), the grind's
  threads on E-cores.

**Where the plan was off:**
- **The recursion AIR's modes cannot form `C(T(name), x)`** for a wire
  pair `x` that no row above outputs (the secret, as `member`, `owner` and
  the nullifier's key need): the tagged composite of three selectors does,
  with no AIR change.
- **The set cannot be `p2` and `qm31` of a three-component circuit:**
  `h8`'s padding uses the zero wire, so the circuit has no `h8` at all.
- **The x86 targets miss** (above): the plan's estimate counted cells
  ("2^11 rows × about 400 columns") but not the 20-bit grind, about half of
  each proof on 4 threads, nor that owner pays the same floor as auth. The
  levers: format 44's PoW 16 (S29's alternative, now with an x86 reason
  beside the phone's grind), a smaller `h` (7.14's option 2: `2·revealed`
  rounded, `h = 256`, floors 2^10), blowup 8 with 29 queries (floor 2^10,
  bytes down) — 7.12's phone gate decides with the phone's numbers.
- **Counts:** 62.93 and 62.92 proven bits on the built set, against the
  plan's model of 62.69 and 62.66.
- **The verifier kit:** a credential proof's bytes need postcard, which the
  kit's lockfile lacks; they sit under `credential-bytes`, which the kit
  drops as it drops `test-formats`.

**Review (Opus):** no high finding; folded M1 (the hidden-state gate
searched fixed little-endian bytes against postcard's varints, so it was
vacuous: now two words of a hidden digest among the published values, the
nullifier's key added, a planted control), L1 (the tagged row's `b = 1`
gate), L3 (words ≥ p refused by the prover), L4 (`selector` asserts a
selector mode), L5 (`verify_with` documented as the circuit-generic step),
L6 (`Circuit::log_sizes` documented: every caller checks the wiring, which
refuses an `h8`-less circuit, first). Not taken: L2 (comparing Merkle
witnesses' lengths: they follow the query positions, the coins, and differ
between two proofs — measured), L7 (the timings are recorded here, not
asserted: they are the machine's).

**Commits:** `9643af7e` the tagged row and circuits without `h8`;
`1eaec998` the Blake2s-M31 stack; `f4e6348c` formats 42 and 44, 30
retired; `0e9ddbd5` the one-component refusal; `0c2e1dff` the credential
AIR, its prover, verifier and gates; `c23cf24b` doc links; `0a863046` the
review's folds; this record.

**Gates** [measured; 12 GiB scope, `nice -n 10`, 8 jobs, other agents'
runs, load 20–86]: `just check` at `0a863046` green through the formatting,
the docs, the no-std builds, the leak gates, the kit, the lints, the core
crates and `test-recair`; in the agent crates `vos-cli`'s `cli` suite
failed 5 of 9 at the node's start under load 50+ (empty logs), and passed
9 of 9 alone; the agent crates rerun with `--no-fail-fast` and
`test-reads`, 691 passed in 53 suites. `just test-proof` green, 579 passed
in 50 suites, the credential suite's leakage at N = 500 among them.

**Review (Fable):** accept; M1, M2, L1–L6 folded
(`research/slice-7/7.10-fable.md`). No soundness or zero-knowledge
defect. The folds:
- **M1, the device hidden-state gate** (`tests/device/leakage.rs`) searched
  8-byte needles in postcard bytes, which varint-encode every M31, so it
  could not fail. It now takes the credential gate's method, moved to
  `common::leakage::leaked`: two or more distinct values of a hidden
  digest among the proof's published M31s; the hidden digests are the
  witness's sixteen words in the Poseidon2 call's two blocks, the call's
  eight output words, and the witness's and the output's bytes eight at a
  time. The control plants the output's words among a queried column and
  is found; on that planted proof the old byte search finds nothing and
  the new one names the output digest [measured, a temporary assertion].
- **M2, the fork's grind** (olanod/stwo `vos/grind-chunks` `4cd1f83f`, on
  `c3ec9813`, unpushed; the workspace, the fuzz crate and the kit's, the
  blob's and the runner's lockfiles re-pinned by rev): a thread's unit of
  work is 2^14 consecutive nonces of one high word's range instead of the
  whole 2^20, the nonce space `(hi << 32) | lo`, `lo < 2^20`, unchanged,
  so the grind returns the same smallest nonce whatever the threads; the
  smallest good chunk lowered by `fetch_min`. The fork's tests: the
  grind's nonce is a scalar scan's smallest, past the first chunk, at 1, 3
  and 8 threads, for Blake2s, Blake2s-M31 and Blake2b. **No fixture
  moved:** 300 seeds' nonces at PoW 20 and 16 are the same before and
  after at 1, 4 and 8 threads (one digest of all of them), and
  `test-proof`'s seeded fixtures pass unchanged. 2^16 chunks measured
  beside 2^14: slower at every count (PoW 20, 4 threads, mean 39.7 against
  34.6 ms on a generic build), so 14.
- **L1:** `Circuit::log_sizes` debug-asserts `h8` is not empty, naming
  `log_sizes_without_h8`.
- **L4:** `a_tagged_rows_free_message_is_refused` (the leaf's tagged row
  on a free message, the member row's yield rebalanced:
  `FreeMessageAbsorbed` at that row) and, in
  `an_honest_proof_of_another_statement_is_refused`, one word fewer and
  one more under `verify_with` (`Logup` or `InteractionPow`).
- **L5:** `credential_timing` proves every statement under 42 and 44 and
  reports p50 and p95 of 40 proves and of 300 grinds at each thread count
  on its command line (1, 4 and 8 by default), a rayon pool each.
- **L2** to 7.16's text (the Blake2s-M31 channel's `mix_bytes` packs four
  bytes a word before a format pins a transcript that mixes bytes);
  **L3** to 7.11's (ingress calls `verify`, never `verify_with`; the fuzz
  target `verify_bytes`; the time to refuse a wrong PoW measured, the
  composition check running before the PoW check in Stwo's order).
- **L6:** the final verifier is single-threaded, so its time is the
  one-core time: 1.61 ms on one thread pinned to one core [measured,
  below], under pin I's 10 ms.

**Decisions** [under S29, at this review; pin I, §7.10, §7.12]: the
owner statement's x86 target of 30 ms is restated as **owner at most
auth's**, the floor being the masking's and shared by both kinds (Q1);
S29's format is chosen on the phone at 7.12, after M2, as planned, the x86
evidence favouring 44 (Q2); the x86 target of 60 ms stays as format 44's,
42's miss recorded (Q3); `h = 256` is a later lever, taken only if PG1
needs it.

**The grind before and after M2** [measured; a standalone bench on each
fork commit, `target-cpu=native`, fat LTO; 300 seeds after 3 warm-ups;
1 thread on core 1, 4 on cores 1, 3, 6, 8 (P-cores), 8 on those and E-cores
12–15; load 2.2–2.8; mean / p50 / p95, ms]:

| PoW | threads | before | after |
|---|---|---|---|
| 20 | 1 | 25.5 / 16.9 / 78.0 | 25.9 / 17.3 / 79.3 |
| 20 | 4 | 27.8 / 27.7 / 31.7 | **9.8 / 6.4 / 28.2** |
| 20 | 8 | 45.7 / 46.6 / 52.5 | **7.6 / 5.0 / 21.7** |
| 16 | 1 | 1.5 / 1.0 / 4.2 | 1.5 / 1.1 / 4.2 |
| 16 | 4 | 3.5 / 3.1 / 7.7 | **1.0 / 0.7 / 2.0** |
| 16 | 8 | 6.4 / 5.9 / 11.2 | **1.2 / 1.1 / 2.0** |

Before, four threads were no faster than one and eight slower (each thread
finishing a whole 2^20 range); after, the grind scales and orders
correctly. The record's earlier "PoW 20, 37–43 ms on 4 threads" was this
artefact.

**Re-timed after M2** [measured; `credential_timing`, the pinning above,
40 proves after 2 warm-ups, 300 grinds; load 2.1–3.3 throughout; prove p50 /
p95, ms; verify p50]:

| statement, format | 1 thread | 4 threads | 8 threads |
|---|---|---|---|
| auth, 42 | 115 / 219 | 51.0 / 79.8 | 44.5 / 66.4 |
| owner, 42 | 114 / 227 | 50.5 / 83.3 | 47.2 / 57.0 |
| membership and payment, 42 | 106 / 227 | 50.1 / 83.5 | 46.0 / 71.7 |
| auth, 44 | 84.7 / 89.2 | **44.6 / 47.5** | 40.6 / 43.6 |
| owner, 44 | 85.2 / 90.3 | **44.0 / 47.2** | 39.6 / 44.2 |
| membership and payment, 44 | 84.1 / 90.7 | **43.7 / 47.6** | 40.2 / 43.5 |
| PoW 20 grind (mean / p50 / p95) | 45.1 / 29.3 / 134.6 | 13.9 / 9.4 / 41.0 | 10.2 / 7.0 / 28.4 |
| PoW 16 grind | 2.5 / 1.7 / 7.1 | 1.3 / 0.9 / 2.6 | 1.5 / 1.4 / 2.4 |
| verify | 1.61–1.71 ms | 2.10–2.22 ms | 2.26–2.43 ms |

R1 3.9–5.1 ms; proofs 195–221 KB (the Merkle witnesses follow the
coins). At 4 threads 44 is inside 60 ms at its 95th percentile for every
statement and owner equals auth; 42's median is now inside 60 ms but its
95th percentile, the grind's tail, is not (80–84 ms). On x86 the grind's
p95 at PoW 20 is 41 ms on 4 threads, under S29's 50 ms; the phone decides.

**Review folds' commits:** `af52e21c` the fork's pin; `b2f1847e` the
device hidden-state gate; `ce231ed0` the gate gaps and `log_sizes`;
`9b7cac32` the timing example; this record with the review and the plan's
amendments.

**Gates** [measured; 12 GiB scope, `nice -n 10`, 6 jobs, other agents'
runs, load 2–23]: the touched suites (`credential` 20, `device` 24, the
fork's grind tests 7, with and without `parallel`); `just check` green;
`just test-proof` green, 579 passed in 50 suites.

## Step 7.11: the verifier at ingress

Branch `s7/7.11`, from vos-core `920103b3`.

**Built:**
- **The wire** (`vos-wire`): `Principal::Anonymous { scope, nullifier }`
  (3) and `Principal::Owner(digest)` (4), never granted a role
  (`is_credential`); the request `ingress::Credentialed`, its
  `CredentialPublic` (the index its kind), `CredentialRefusal` (the codes in
  check order) under `Rejection::Credential` (9); the session-less input
  `batch::Input::Credentialed` (10, boxed) carrying `CredentialedInput`
  (the origin, the call, `b`, `expires_ms`, auth's root; no proof, nonce or
  format) and its step's `InputRef::Credentialed { binding }` (9);
  `schema::CredentialGuard` (`Auth { name, device, once }`, `Owner`) in
  `MethodSchema::credential`, validated (a command's alone, no role, not
  linearizable, a name of 1–64 bytes), and `Schema::credentials`; a
  program's section carries both after its methods, as `Credentials`, only
  when there is a guard or the mark, so an unguarded program's section is
  the one it carried before; `credentials::scope` and `credentials::Bound::digest`
  (the binding digest, the arguments with their `u32` length) and
  `credentials::binding`; the system rows `credentials` (the actor's
  instance), `binding(b) → expires_ms` and `once(scope ‖ nullifier) → t`,
  and `Due::Binding(b)` (kind 2, its 32 bytes the id), which the sweep's
  step lists (`Step::Swept { due, bindings }`) and accumulate forgets, a
  sweep listing up to 64 of them beside its 32 sessions' and workflows'
  rows (`keys::SweepBudget`, `defaults::SWEEP_BINDINGS`), a refine
  reserving `DECODE_DUE` (2,000) per listed row;
  `Failure::Credentials` (15); refine's `CredentialExpired` (7),
  `Replayed` (8), `StaleRoot` (9), `Once` (10); `defaults::
  CREDENTIAL_HORIZON_MS` (120 s) and `BINDING_KEPT_MS` (60 s).
- **The apply rule** (`agent/default/src/refine/credentialed.rs`), by the
  batch's time: refused, writing nothing, if expired, if `b` is recorded,
  for auth if the root is not the ring's newest or superseded at most
  `ROOT_MAX_AGE` before, for `once` if the nullifier is admitted; else `b`
  and its due row recorded whatever the method does, the method run as the
  origin (an auth origin whose scope is not its guard's `Forbidden`), and a
  `once` nullifier recorded only on `Ok`, in the same step. A guard admits
  its origin's kind alone and a method without one refuses a credential's
  origin (`invoke`); an install records the credential actor's row, and
  fails `Failure::Credentials` for a second actor, for the actor's instance
  replaced by another program, and for an auth guard with no actor; a
  `SetRole` naming a credential's origin fails `Forbidden`.
- **The SDK:** `#[msg(credential = Auth("vote"), once)]`,
  `#[msg(credential = Owner)]`, `device = "..."`, each refused off a
  `&mut self` handler or beside a role or `linearizable`;
  `#[actor(credentials)]` (`vos_sdk::state::Marked`), which picks the
  marked section of the two `#[messages]` makes (`runtime::schema_section`); `ctx.owner()` and `ctx.nullifier()`; the caller's buffer 65 bytes,
  an `Anonymous`'s. `vos-credentials` is `#[actor(credentials)]`.
- **The ledger** (`agent/test-actors/purses`, the demo's in 7.13): rows by
  name (1–32 bytes of UTF-8), each `(owner, balance, frozen)`;
  `invite_row` and `mint` under `operator`, `claim_row` by any caller
  before the invitation's expiry and only for the digest it names;
  `transfer(from, to, amount)` under `Owner`, debiting `from` only while
  its live owner is the proof's digest and it is not frozen, crediting
  `to`, which must exist; `balance`, `row`; `rekey` (lifts a freeze) and
  `freeze` under `operator`. And `poll`: `vote` (`Auth("vote")`, `once`),
  `vote_again` (`Auth("vote/2")`, `once`), `login` (`Auth("login")`).
- **Ingress** (`node/host/src/credentialed.rs`): the node API's
  `Credentialed` (0x0104, 1,642,496 bytes; the node's HTTP and the
  gateway's `POST /agents/{a}/credentialed` a body of 4 less); the checks
  in pin I's order on the replica's applied state, the format the proof
  registry names as the final verifier pins it (`credential::FORMAT`, no
  literal); then a verification slot (`Config::verifications`, by default
  twice the executors; past it `Busy`), and the final verifier's
  `credential::verify_bytes` on an executor (picking the circuit by kind);
  the `credential` stage in the node's stats. A verified call goes to the
  leader, queued outside any lane (`Pending::Credentialed`), forwarded by a
  follower as a call is (`PeerMessage::ForwardCredentialed`, 19), and is
  answered once this replica applied it. A `Grant` naming a credential's
  origin is `Malformed`. The client's `credentialed` and `time`.
- **The fuzz targets** `credentialed_decode` and `credential_verify_bytes`
  in `just fuzz`, their replay seeds (an honest proof of each kind) from
  recair's `credential_ingress --seeds`; **`node/SECURITY.md`**.

**Tests:**
- **The wire** (`agent/wire/tests/wire/credentialed.rs`, `abi.rs`): the
  origins' indexes; the request, its public statement and the refusal codes
  in order under `Rejection`'s 9, pinned; the logged input (10) without the
  proof; `b` as BLAKE2b-256 of its fields at their widths, each field
  changing it; `binding` and `scope` as their compressions, two agents',
  two spaces' and two names' scopes distinct, and two spaces sharing a
  handle giving one secret two nullifiers; the rows and a binding's due row
  read back; the guards' validation, the section without guards byte for
  byte the old one, the mark alone after it, an empty mark refused; the new
  codes; the ring's row key (`credentials::ring_key`, which ingress and
  the refine share).
- **Apply** (`agent/testkit/tests/agent/credentialed.rs`, the default
  agent): an auth guard refused an install without the credential actor, a
  second actor and the actor's instance replaced each `Failure::
  Credentials`; owner proofs paying from their rows (the live owner's
  alone, nothing from a frozen row, a rekeyed row from the new owner's, a
  transfer to no row refused with the payer's balance kept, a claim of a
  digest the invitation does not name and one past its expiry refused, the
  operator's methods under its role); an origin admitted by its guard alone
  (an owner proof to an unguarded method, an auth proof to an owner guard,
  a client to a guarded method, each `Forbidden`, the binding recorded; no
  role granted to a credential's origin); apply's refusals writing nothing
  (an expired call, a recorded binding from another replica's copy and from
  a twin in one batch, a root never held) and the sweep forgetting a
  binding and its row; an auth root fresh for `ROOT_MAX_AGE` after a
  revocation superseded it and `StaleRoot` a millisecond later, a scope not
  the guard's `Forbidden`; `once`: a refused vote leaving the nullifier
  free while its binding is `Replayed`, a second admitted vote `Once`,
  another scope's guard admitting it; a credentialed call's own work under
  a step's reserve on both hosts with the ring full (64 roots): 69,601
  on VOS, 154,040 on JAM, of 300,000; the batch's first auth call, which
  pays and decodes the ring once for the refine, 157,212 and 241,725.
- **Ingress** (`node/host/tests/served/credentialed.rs`, three nodes of a
  founded space, real proofs): each refusal in its check order (413 from
  the head past the frame; `Malformed`; `NoAgent`; `NoSpace` at an
  uninstalled agent; then one request failing every check from the format
  on, mended a check at a time: `Format` for a 1.4 MiB format-43 body,
  `Size` for it under the credential format and for a 600 KiB proof,
  `Expiry`, `Method`, `Kind`, `Scope`, `Binding` (and a real proof sent
  with another call's arguments), `RootUnknown`, `Proof`), the call
  running, `Replayed` sent again, `Once` before `RootUnknown`, a wrong-PoW
  proof `Proof`, no log entry holding a proof's bytes; a replay and a
  `once` race sent to the leader and a follower with the leader's refines
  held: one runs, the other `Replayed` and `Once` at apply, another scope
  admitting the nullifier; a root a lagging replica (its commits held) has
  not applied `RootUnknown` there and admitted at the leader, a root
  replaced at its own batch time (the clock held back) and one pushed out
  by 68 later roots each `RootUnknown` and admitted on the path fetched
  again; a revoked member admitted within `ROOT_MAX_AGE` and `RootStale`
  past it; owner proofs paying, an old owner's failing after a rekey; a
  call sent to the leader and one forwarded by a follower, the leader's
  refines held, each giving its large body's place back once verified,
  before it applies.
  `ingress::api`'s per-kind header sizes cover `Credentialed`; the budget's
  places (`credentialed::tests`); the large bodies' places by kind and
  size (`api::tests`).
- **The gateway** (`node/gateway/tests/gateway.rs`): a credentialed call,
  one that does not decode and one to no agent answer through the gateway
  as through the node's HTTP, the node's `NoSpace` passed on; `GET /time`.
- **Pricing:** a sweep of 32 sessions and 64 bindings under its reserve;
  decoding a sweep of its most rows under `batch_start`.

**Measured** [measured; this machine, Intel Core Ultra 7 155H, 22 logical
threads (6 P-cores with SMT, 8 E-cores, 2 LP E-cores)]:
- **The verifier, one thread** (`recair`'s `credential_ingress`, core 1,
  200 runs after two warm-ups, median / p95): auth verified in 1.87 / 2.11
  ms, owner 1.78 / 1.85 ms (pin I's ≤ 10 ms); **a wrong PoW refused in
  0.66 / 0.70 ms** (owner 0.62 / 0.65), under pin I's 1 ms though the
  composition check runs before the PoW in Stwo's order; a wrong
  interaction PoW 0.48 / 0.52 ms; a proof cut by a byte 0.18 / 0.18 ms.
  Proofs 196–206 KB.
- **The executors' bound (S44), on this laptop** (`cargo bench -p vos-node
  --bench credentialed`, after the review's folds; one node of a founded
  space of one, 4 agents, owner transfers over the API's socket, open loop
  at `100·k` a second for 10 s, a call answered `Busy` sent again a
  millisecond later; a signed increment at the same rate beside; the
  node and the generator in one process; `N` = 22 logical threads, 16
  physical cores of which 6 performance cores). k = 1 to 8 in one run
  (load 6.4 at its start, the generator's proving then at 22); k = 16
  and 22 in another (load 3.8 at its start, 10 to 24 while it ran, from
  other agents' builds):

  | k | asked | achieved | credentialed p50 / p99 | signed p50 / p99 | verify mean | its executor wait | in flight (mean / most) | `Busy` | |
  |---|---|---|---|---|---|---|---|---|---|
  | 1 | 100 | 100 | 5.2 / 7.0 ms | 3.6 / 5.1 ms | 1.81 ms | 0.01 ms | 0.5 / 2 | 0 | within |
  | 2 | 200 | 200 | 5.4 / 6.7 ms | 3.2 / 4.3 ms | 1.98 ms | 0.01 ms | 1.1 / 2 | 0 | within |
  | 4 | 400 | 400 | 5.8 / 7.1 ms | 3.2 / 4.4 ms | 2.29 ms | 0.01 ms | 2.3 / 5 | 0 | within |
  | 8 | 800 | 799 | 6.8 / 14.7 ms | 3.3 / 4.6 ms | 2.72 ms | 0.01 ms | 5.8 / 16 | 0 | within |
  | 16 | 1,600 | 1,037 | 2.6 / 5.4 s | 5.6 / 11.1 ms | 14.4 ms | 10.5 ms | 91.8 / 96 | 5,422 | **missed** |
  | 22 | 2,200 | 953 | 6.5 / 13.0 s | 8.9 / 18.1 ms | 17.7 ms | 4.6 ms | 95.2 / 96 | 733 | **missed** |

  A first k = 16 run (load 2.4 at its start, 40 before it ended) took
  1,281 a second, a verification's mean 11.4 ms after 7.8 ms of wait.
  Each run's proofs are made first, on every thread (about 30 a second
  here, 15 to 22 minutes for k = 16 and 22 on the shared machine), each
  good until 115 s past when making them is expected to end, so a run
  lasts its 10 s or longer. The bound holds to k = 8, where a
  verification takes 1.8 to 2.7 ms and waits for no executor. At k = 16
  and 22 it is missed, and not by the places' cap the review found (the
  calls in flight now stop at the generator's 96 senders, past the 64
  places, which are given back once a proof is verified): the
  verifications run at 11 to 18 ms each against 1.8 on a performance
  core alone, so the executors themselves saturate (16 × 1 / 14.4 ms is
  1,100 a second; 22 × 1 / 17.7 ms is 1,240), the generator's senders
  and proofs, the node's runtime and applies, and other agents' builds
  sharing the 22 threads. `100·k` a second on `k` executors leaves each
  call 10 ms of an executor, verification and apply together, so a host
  whose threads verify in more than about 7 ms under full load misses
  the gate as S44 worded it, whatever the node does; the previous table's
  k = 22 miss (1,738 a second over a 1.4 s run, before these folds) was
  also the 64 places held through the apply wait (64 / 1,738 a second
  is 37 ms a call). S55 measures the gate on compumax, the node pinned
  to its performance cores, the generator on the desktop over QUIC
  (`credentialed serve` and `drive`), runs of 10 s; this table is the
  laptop's.
- **An honest proof refused** [measured]: of 30,000 owner proofs made
  and verified directly (`verify_bytes`), one was refused
  (`Stark(Fri(InnerLayerCommitmentInvalid { inner_layer: 7, error:
  RootMismatch }))`), and one of the bench's 16,000 at k = 16 was
  answered `Proof` at ingress: a completeness failure of the format-42
  prover and verifier pair at about one proof in 30,000, found here and
  not fixed in 7.11 (below, left).
- **Under format 44, at the merge with 7.12** [measured; the same laptop,
  another agent's proving stress beside it, load 11 to 18]: the
  verifier on one core (`credential_ingress`, core 3) auth 5.52 / 10.26
  ms, owner 5.48 / 10.35, a wrong PoW refused in 1.56 / 2.18, a byte cut
  0.43 / 0.45; the cut's refusal, which no format changes, ran 2.4 times
  its quiet 0.18 ms, so the machine, not the format, is most of the
  rise. The rate bench at k = 1 and 4 (`-- 1 4`) missed under that load:
  76 and 301 a second of 100 and 400, credentialed p50 / p99 1.9 / 4.1 s
  and 2.2 / 3.4 s, signed 5.5 / 6.7 and 5.3 / 7.3 ms, a verification's
  mean 12.0 and 12.6 ms after 10.9 and 10.7 ms of executor wait, the
  proofs made at 10 a second (30 quiet); every honest proof of the 5,000
  verified. A quick sanity of the format change, not the gate: S55's run
  is the gate's.

**Where the plan was off:**
- **The schema's section** could not simply grow a field: the section is
  in every kernel's read-only data, so a byte more in every program's
  section moved `WINDOW_PROGRAM` and the fixtures with it. The guards and
  the mark follow the methods only when there are any, so unguarded
  programs keep their sections byte for byte. `BALANCE_PROGRAM` moved all
  the same: its served reads format a row key's `Failure`, which gained
  `Credentials` (re-pinned in `pvm/proof/src/constants.rs`; no fixture
  holds it). `WINDOW_PROGRAM`, `PREDICATE_PROGRAM` and the derive pins
  are unchanged.
- **A larger principal** (an `Anonymous`'s 65 bytes, the request's caller
  copied in every decode) and the guards' field raised the agent's own
  costs past their reserves: `DECODE_INPUT` 6,000 → 7,000,
  `INSTALL_RESERVE` 9M → 10M, `RECORD_BYTE` 64 → 68; refine's `Call`
  takes its caller by reference. The SDK's caller buffer grew to 65 bytes.
- **A VOS node logs work results,** not batches: "the origin logged"
  holds of the batch refine (and a JAM package) carries; the node's log
  carries the run's effects and `InputRef::Credentialed { b }`, and the
  test asserts no entry holds a proof.
- **The format number:** ingress admits the final verifier's
  `credential::FORMAT`, which its test pins to the registry's
  `CREDENTIAL_PROOF`, so 7.12's choice of 44 moves one constant.
- **`Time`** and `GET /time` were 7.10b's; 7.11 added the client's `time`.
- **The binding set's sweep** needed its own budget (the review's M3) and
  a refine its decode reserve per listed row: the leader's first listing
  of 288 rows ran past `batch_start` and trapped the refine.
- **Busy** is tested on the budget's places, not end to end: a
  credentialed call reaches the slot only past every state check, on a
  founded space whose harness fixes the node's config.

**Review (Opus):** no high finding; the authority core (the binding's
fields, the program by kind, `verify` never `verify_with`, the twin in one
batch, the `once` row on `Ok` alone, every invocation gated, no role for a
credential's origin, one scope source, the ring's key, the binding kept
past any copy's admission) checked and holding. Folded: M1 (credentialed
bodies of 1.6 MB counted against no budget: their own places, 64 on the
node API and on each HTTP front, apart from the installs'); M2 (a
follower answering a forwarded `Replayed` before it applied the first run,
so a client reading state there could pay again: answered once it holds
the binding); M3 (binding rows in the sweep's 32 could hold timers back:
their own budget of 64, and a decode reserve per listed row); L1 (a
credentialed call's own work measured on both hosts); L2 (the budget's
place goes with the executor's job); L3 (a statement with a word at or
above p spends no verification); L5 (a ring the meter cannot pay consumes
the input unrecorded: documented); the nits (the module doc's "before its
proof is decoded"; a forwarded input's trust in `node/SECURITY.md`). Not
taken: L4 (ingress decodes the instance's installed record per request:
a cache per installed version is for 7.13's load, noted).

**Review (Fable):** fix-then-merge; M1–M3 (+Ls) folded
(`research/slice-7/7.11-fable.md`). The authority core, the check order,
the apply rule and the replicated rows found as pinned. Folded:
- **M1** (a credentialed body and its large place held through the apply
  wait and a forward's, up to 30 s: the node's credentialed concurrency
  64, and one member with 64 valid proofs to a follower of a slow leader
  could hold every place): the body is dropped once decoded and the place
  goes with the proof once it is verified (`api::LargePlace`, handed from
  the socket, QUIC and the node's HTTP, whose server now hands a large
  body's place to its handler, `vos_http::Request::large`, and drops the
  request's bytes from its buffer before the handler runs). Tested served
  (a call to the leader and one forwarded by a follower, the leader's
  refines held, each place given back before the apply) and by kind and
  size (`api::tests`, the review's L8). The gateway keeps its body, and
  its place, until the node answers, as it relays the body whole:
  `node/SECURITY.md` says so.
- **M2** (the ring paid `RECORD_BYTE × len` and decoded on every auth
  call, measured on a ring of two): paid and decoded once a refine
  (`Base::ring`, cleared by a step writing the ring's row and by an admin
  step), re-measured on a full ring (above, both hosts).
- **M3**: this entry's rate paragraph, `node-api.md` (credentialed bodies
  are large, their places given back once verified), `node/SECURITY.md`
  (the places' concurrency, the gateway's, the binding drain).
- **L1** (a follower lagging past a binding's sweep answering a forwarded
  `Replayed` as `TimedOut`): it answers `Replayed` once it holds the
  binding or has applied a batch past the call's expiry, by then the
  run's batch is applied there.
- **L2:** `credentials::ring_key`, the ring's row key once, for ingress and
  the refine, pinned by a wire test.
- **L3:** `first_due` reads the due index to its first row, not a sweep's
  listing.
- **L4:** the drain stated (`defaults::SWEEP_BINDINGS`,
  `node/SECURITY.md`): 64 bindings a sweep, a sweep a batch while rows
  are due, so sustained credentialed calls past 64 a batch grow the
  binding rows until the load falls, and more than 96 due bindings ahead
  of a session's or a workflow's row hold that row until they drain. The
  rate bench's heaviest load (2,200 a second over four agents, 550 an
  agent) stays under it while each agent runs 9 batches a second or more.
- **L5:** with M3.
- **L6:** the 7.10b hand-off on the operator nonce margin was taken
  before 7.11, on vos-core (`21c8c1d6`, `api::operator::may_forget`: a
  nonce kept `HORIZON_MS` past its expiry); the review read the branch's
  own commits only.
- **L7:** the bench prints the calls in flight (mean and most), the
  verifications' executor wait (the node's `credential_queue` stage) and
  the `SENDERS` bound, and sends a call answered `Busy` again.
Not taken: the note on the apply-time scope re-check (kept; it guards
against a node logging a scope not its guard's, and costs a hash and a
compression). Q1 answered by the owner as S55 (above, and the plan's
pin I and 7.11 gate).

**Left:**
- **S55's run on compumax** (the owner at the key; scheduled apart): the
  node under `taskset` on the performance cores, `credentialed serve
  --listen 0.0.0.0:PORT --executors k`, the desktop running the `drive`
  line it prints, for each `k` up to those cores; `N` recorded as the
  physical cores and the logical threads.
- **The honest proof refused** (above): one format-42 owner proof in about
  30,000 fails its FRI inner layer 7's decommitment (`RootMismatch`), a
  completeness failure of the prover and verifier pair (the masked
  prover and the Stwo fork's FRI), not of ingress; a member's device
  proves again and the call goes through. The failing proof, the
  `Credentialed` encoding of a bench call, was kept outside the
  repository for whoever takes it up.
- The gateway's HTTP holds a credentialed body's place until the node
  answers (`node/SECURITY.md`); handing it back once the body is sent on
  would need the upstream's request split from its answer.

**Commits:** `18d1a80f` apply, the guards, the rows, the ledger; `43d2a87f`
ingress, the kind, the gateway's route, the tests, the bench, the fuzz
targets, `node/SECURITY.md`; `f5ae9fdf` the budget's places, another
call's arguments, two spaces' nullifiers; `c36fe3c6` the decode target;
`29bca4ed` the review's folds; `b909b175` the section format and the
balance kernel's re-pin; this record and the bench's sizing. The Fable
review's folds: `3655d50d` M1 and the executor wait; `b8301c48` M2 and L2;
`f0ba9262` L1 and L3; `1941c258`, `cfdd2ef4`, `a7928932`, `ee3ad377`,
`c6cc3a16` the bench (L7, its 10 s runs, its `serve` and `drive` modes);
`242f275d` M3, L4 and L5 in the docs; `285e939c` S55; `db432858` the
review and this record; `fa91abb8` vos-scale's requests; `4b3e0e68` the
ring's key inline (as a plain function it moved `WINDOW_PROGRAM`, the
wire's codegen shifting though the window kernel never calls it); the
gates.

**Gates** [measured; 12 GiB scope, `nice -n 10`, 8 jobs, other agents'
runs on the machine]: the touched suites (the wire's 51, the testkit's
166, the served `credentialed` 4, `ingress` 41, the gateway's
differential corpus, `vos-node`'s 81, the compiler's, `kernel
constants::`, the prover's `masked`); the two new fuzz targets' replays;
`just check` green at `43fac86f` (exit 0, 1,626 passed in 122 suites). Not run:
`test-proof` beyond `kernel constants::` (no AIR or fixture moved), the
gateway's `ssh` feature. Fixed on the way: `prove::the_slot_does_not_move_the_shape`
compared each tree's queried values per column, which follow the distinct
query positions (42 or 43 as the coins fall): it compares the trees'
columns.
After the Fable review's folds [measured; the same scope, other agents'
runs on the machine]: the wire's `credentialed` 6, the testkit's
`credentialed` 6, the served `credentialed` 5, `vos-http`'s, `vos-node`'s
`api::` and `credentialed::` units; `just check` green at `4b3e0e68`
(exit 0, 1,629 passed in 122 suites). The rate bench as above; the
compumax run is S55's, left.

## Step 7.12: the device library and the credential phone gate

Branch `s7/7.12`, from vos-core `920103b3`.

**S29 decided: format 44.** The rule: the grind's 95th percentile on the
phone above 50 ms takes PoW 16 at 47 queries (44), else PoW 20 at 43
(42). The grind is the fork's chunked one (olanod/stwo `vos/grind-chunks`
`4cd1f83f`: 2^14 nonces a chunk, the smallest nonce kept), timed alone on
the Blake2s-M31 channel, 300 grinds a run [measured; Fairphone 6, session
P2 below; `research/slice-7/phone-fairphone6-p2.txt`]:

| PoW | threads | mean / p50 / p95 / max, ms | runs |
|---|---|---|---|
| 20 | 8 (automatic) | 24.5–24.9 / 16.1–16.6 / **68.9–71.9** / 179 | 4 |
| 20 | 4 big cores (`taskset f0`) | 36.5–40.3 / 23.2–26.8 / **110–119** / 309 | 2 |
| 16 | 8 | 4.0–4.3 / 3.6–3.8 / **6.2–6.9** / 28 | 4 |
| 16 | 4 big cores | 2.7–3.9 / 1.8–3.4 / **5.2–7.9** / 16 | 2 |

PoW 20's 95th percentile is above 50 ms at every thread count, so **44**
is registered and admitted, and **42 retired** (proofs were made under it;
a number names one set of parameters). 30 stays retired unregistered. The
same decision run proved under both formats (recair's `credential_timing`,
the system allocator, 40 proves): at 8 threads auth p50 / p95 161.6 /
202.5 ms under 42 and 154.0 / 178.3 under 44; on four big cores 163.1 /
266.2 under 42 and 147.3 / 156.5 under 44: 42's tail is its grind's.

**Built:**
- **Format 44** (`vos_pvm_proof::format::CREDENTIAL_PROOF`, number 44, 47
  queries, PoW 16, 110 / 62, admitted; `RETIRED` gains 42): the final
  verifier's constants re-pinned (`FORMAT`, `CONFIG`, `PARAMS`; the
  preprocessed roots unchanged, the same columns at the same blowup; both
  program ids new, they hash the format); recair's tests prove under 44,
  and a proof under 42's parameters is refused under 44 (and a proof
  relabelled 42 refused as `Format`); the count test keeps 42's 106 / 62
  for the record; `pvm/proof/SECURITY.md`'s table.
- **`vos-device`** (`pvm/device`, `std`; pins K and L):
  - `source_input` (SHA-256 of `vos/device/input/v1` ‖ handle),
    `derive_secret` (BLAKE2b-512 of `vos/device/secret/v1` ‖ handle ‖ o,
    eight `u64`s mod p; `w` zeroized), `DeviceSecret` (zeroized on drop,
    no `Clone`, no `Debug`), `member`, `owner`;
  - `Call` (`new` draws the nonce from the OS), `binding_digest` and
    `binding`, `scope` (the name 1–64 bytes, SCALE as `proving.md` §8
    pins it);
  - `Prover` (`ProverConfig { threads, max_memory, masks }`):
    `prove_auth` (the witness checked first, `Witness` before any
    proving), `prove_owner`, `prove_membership_and_payment` (the joint
    circuit: its own program id, kind byte `0xff`); the secret's words
    and the circuit's private values zeroized after each proof;
    `Threads::Auto` one thread a core, an even split, `Count`, `Cores`
    (pinned by `sched_setaffinity`); `PEAK_BYTES` (192 MiB) below which
    `new` refuses `Memory`;
  - `verify` (the format the registry's, the binding the call's under the
    kind's program, auth's scope the guard name's, then the final
    verifier by kind) and `verify_joint`;
  - `wire`: `time_request` / `time_answer`, `path_query` / `root_query`
    (`QueryCall`s signed over the agent's identity by a key drawn for each,
    the replica's applied state), `path_answer` / `root_answer`,
    `credentialed` (identity §5's body after the agent's id) and
    `credentialed_answer` (`Ran`, `RootUnknown`, another credential
    refusal by code, any other answer);
  - `PathKeeper`: due with no path, when a `root()` answer moved, or on
    its timer (30 s, a twentieth of `ROOT_MAX_AGE`, jittered uniformly by
    half a period either way); `update` refuses a path not its member's;
    `unknown` drops the path and halves the period (to 1 s), a fetch
    finding the root unmoved doubles it back;
  - its `SECURITY.md`: the secret's containment (what is zeroized and what
    is not: the trace and its masked polynomials, the hashes' states),
    what the library shows, the witness and the call, paths.
- **`node/SECURITY.md`**, new here (7.11's, unmerged, has the fuller
  surface): the path leak stated as reduced, not closed (operators learn a
  digest is online and its address, not when it proves), the refetch after
  `RootUnknown` linking that one fetch to its proof, a tree change showing
  the online members.
- **`tools/phone`** (`vos-phone`): `run` (one child process a cell, so a
  cell's peak is its own: p50, p95, min, max, verify, bytes, distinct
  proofs, SHA-256, `matches_x86`, peak resident from `VmHWM`; then the
  grinds at PoW 20 and 16) and `verify DIR` (a phone's proofs verified on
  x86); `--features seeded` (recair's seeded masks, the x86 run's hashes
  compiled in) and `mimalloc`. `tools/phone/build.sh` (`just phone`):
  the x86 seeded run's references, then both Android binaries with
  `cargo ndk -t arm64-v8a -P 30` against NDK 28.2.13676358, stripped.
- **The plan's text:** pin I's format paragraph and identity §5's
  `format` now 44; `proving.md` §8's format and a "Built" note for the
  library; S29's open question closed.

**Tests** (`pvm/device/tests/device.rs`, 8, in `check`'s core crates):
the derivation against SHA-256 and BLAKE2b-512 computed apart; the scope
and binding against their preimages, each field changing them, the
name's bounds; each proof verified against its call and refused against
other arguments, another name, no name, a relabelled format, a flipped
byte, another secret's owner digest; a bad witness refused before
proving (another member's path, a sibling changed, a word ≥ p, a slot's
bit flipped, another secret's joint); the configuration (memory below
`PEAK_BYTES`, no threads, no cores; `Auto` a thread a core; two pinned
cores prove); the wire (every request decoded back, each query's
signature checked with `verify_strict` and its key fresh, the answers,
the body's layout); the keeper's timer and `unknown`; and **a
`RootUnknown` answer refetching and proving anew**: a member's path held,
64 tree-changing batches a second apart push its root out of `Ring` while
it is still within `ROOT_MAX_AGE` (`Unknown`, not `Stale`), ingress's
`[2, 9, 10]` decodes as `RootUnknown`, the keeper drops the path and is
due, the new path's root is accepted by the ring and the new proof
verifies, under the same nullifier.

**Phone gate PG1** [measured; session P2, 2026-10-27 15:56–16:02; Fairphone
6, SM7635, Android 16 (`FP6.QREL.16.111.0`); battery 77–78%, 30.0–31.0 °C
at every round's start and end, USB powered, the phone's load average
1.3–1.7 before the runs; `vos-phone` built with mimalloc; 20 proves a cell
after 2 warm-ups; three seeded rounds and one timing round at automatic
threads (8), 60 s apart, and one seeded round on the four big cores]:

| statement | gate | automatic threads, p50 / p95, ms (per round) | 4 big cores, p50 / p95 | peak resident | bytes |
|---|---|---|---|---|---|
| auth | ≤ 250 (target 150) | 166.1 / 197.1, 163.8 / 180.3, 168.5 / 184.3; timing 170.1 / 185.0 | 129.4 / 146.7 | 113–132 MiB | 216,762 |
| owner | ≤ 150 | 166.2 / 203.4, 164.9 / 184.7, 161.4 / 169.5; timing 179.0 / 187.3 | 130.7 / 153.9 | 116–133 MiB | 216,815 |
| membership and payment | ≤ 250 | 161.4 / 193.4, 162.7 / 172.2, 163.4 / 190.2; timing 164.0 / 180.5 | 126.1 / 141.5 | 117–119 MiB | 220,441 |

- **Met:** auth within 250 ms (median of the rounds' medians 166 ms, the
  worst 95th percentile 197 ms), membership and payment within 250 ms
  (163, 193), each within 256 MiB (at most 133 MiB); every proof verified
  on the phone (verify 23.6–26.6 ms at automatic threads, 3.8–3.9 ms on a
  big core); the phone's proofs pulled and verified on x86 (`vos-phone
  verify`, the timing build's and the seeded build's, a flipped byte
  refused); **the seeded build's bytes equal x86's** for all three, every
  rep (`matches_x86` true, one distinct proof a cell, at 8 threads on the
  phone and at 1, 3 and 22 on x86: the chunked grind's nonce is the
  smallest whatever the threads).
- **Missed:** auth's target of 150 ms at automatic threads (166), met on
  the four big cores (129 / 147); **owner's 150 ms** at automatic threads
  (p50 161–179), met on the big cores at the median (131) but not at the
  95th percentile (154). Owner costs what auth does, as on x86 (7.10's
  review restated the x86 target as owner at most auth's, the floor being
  the masking's): the shape is the floor's, `4h = 2^11` rows a component
  whatever the circuit, so owner at most auth's holds (equal within the
  noise) while 150 ms is out of reach at automatic threads without a
  lever.
- **The breakdown** (the decision run, 44, 8 threads): the PoW-16 grind
  about 4 ms (p95 7), R1 12–13 ms, verify-free prove the rest, about
  140 ms: the masked prove of two components at 2^11 rows (columns at
  2^12, the composition at 2^13, the trees at 2^15).
- **The levers, in order:** (1) threads by core class (7.17): the even
  split over all eight cores is about 22% slower than four threads on the
  big cores (166 against 129 ms for auth), the little cores (A520-class
  at 1.8 GHz) holding the split back; (2) `h = 256` (7.14's option 2),
  floors 2^10, the masked prove about halved, at the price of a re-pin
  and a measured R1 retry rate; (3) blowup 8 with 29 queries, floor 2^10.
  None is taken here: PG1's two hard budgets hold, and S29's choice is
  made.

**x86** [measured; `vos-phone` timing build, 4 threads on cores 1, 3, 6,
8, 20 proves a cell, quiet (load 3.5 falling)]: auth p50 / p95 44.0 / 46.8
ms, owner 41.4 / 44.6, membership and payment 42.6 / 49.2, as 7.10's
`credential_timing` found under 44; verify 2.1–2.2 ms; peak 137–153 MiB;
the PoW-20 grind p95 37 ms, PoW-16 2.2 ms. The phone at automatic threads
is about 3.8 times x86 on four P-cores, on its four big cores about 2.9.
A first x86 run under another agent's credential run (about 21 cores
busy, load 7–24) took 425–469 ms at the median: discarded.

**Where the plan was off:**
- **Owner at most 150 ms** on the phone is out of reach at automatic
  threads for the reason 7.10 found on x86: the masking's floor, not the
  statement, sets the cost.
- **`Threads::Auto`'s even split costs** about a fifth on this phone
  against the big cores alone: 7.17's weighting is the first lever, now
  with a phone number.
- **The scope's name:** `proving.md` §8 pins it in SCALE (a `u32` length,
  then the bytes), and this library hashes it so; 7.11's
  `vos_wire::credentials::scope` (unmerged) hashes the name's bytes alone,
  so every auth proof from this library would be refused `Scope` by 7.11's
  ingress as it stands. One of the two changes at the merge; the pinned
  text says the library's.
- **The API grew** (recorded in `proving.md` §8's "Built" note): the joint
  proof and its verifier, `ProverConfig::masks`, `Result` where the OS's
  randomness may fail, `PathKeeper::unknown` and `credentialed_answer`.
- **The Android build is the NDK's** (bionic, dynamically linked, API 30),
  not the static musl build P1's spike used; nothing but mimalloc compiles
  C.

**For 7.11's merge:** `vos-device`'s `wire` mirrors identity §5's
`Credentialed` body and the `Rejection::Credential(RootUnknown)` bytes
(`[2, 9, 10]`), and `call` the binding and scope: at the merge they move
onto `vos_wire::ingress::{Credentialed, CredentialPublic,
CredentialRefusal}` and `vos_wire::credentials::{scope, Bound, binding}`,
with a test that the library's request decodes as 7.11's and its proof
passes 7.11's ingress; the scope's name encoding settled first (above);
7.11's fuzz replay corpora (`credential_verify_bytes/auth`, `owner`) were
made under 42 and are made again under 44; `node/SECURITY.md` keeps 7.11's
text, its path entry taking this one's specifics (the timer, the
`RootUnknown` refetch).

**Review (Opus):** no high soundness or secret-handling finding; one
high merge blocker, H1, the scope name's encoding against 7.11's (above):
`proving.md` §8's SCALE kept, pin I's and identity §7's formula lines now
say so, and a vector pinned (`SCOPE_VECTOR`) for 7.11's `scope` to meet.
Folded: M1, the seeded masks were a public `ProverConfig` field any
consumer could set once another crate unified recair's feature: the
masks are now always the OS's, and the seam is `vos-device`'s own
`seeded-masks` feature (`Prover::seeded`, the bench's `seeded` build its
only user), with a `check-no-seeded-masks` row for the library's default
build. M2, a moved root made every online member fetch at once: `due`
now brings the fetch forward to a time drawn below 10 s after the move is
first seen, and the client's duties (its own jittered `root()` polls, a
connection apart) are stated in both `SECURITY.md`s. L1, `verify` checks
the arguments' cap and says it runs the stateless checks alone. L2,
`credentialed_answer` decodes a refusal exactly (`Expiry { now }` kept,
`RootStale` its own answer, a code past `Proof` or a trailing byte
refused). L4, `AuthWitness`'s `Debug` shows nothing. L5, the statement's
secret zeroized by a drop guard, unwinding included; recair's `Context`
copy added to `SECURITY.md`'s "does not". L6, auth proofs with a changed
nullifier or root (words the call does not fix) refused by the proof
itself. Not taken: L3 (a path older than the one held: `path` answers no
`since`, and an older root the ring holds is still accepted within
`ROOT_MAX_AGE`), L7 (the OS's randomness failing reported as `Prove`, as
documented). For the merge: 7.11 replaces `vos_api::CREDENTIALED` with
`Kind::Credentialed`, which `wire.rs` then names.

**The merge with 7.11** (vos-core `7b78d9af`):
- **The scope's name in SCALE** everywhere: `vos_wire::credentials::scope`
  hashes the name's `u32` little-endian length before its bytes, as
  `proving.md` §8, pin I and identity §7 pin it; ingress, the apply-time
  check and the fuzz target call it, and `vos-device`'s `scope` and
  `Call::binding_digest` are now `vos_wire`'s `credentials::scope` and
  `Bound::digest`, one computation for both sides. The wire test pins
  `SCOPE_VECTOR`. No pin moved: `kernel constants::` passes unchanged
  (`WINDOW_PROGRAM`, `BALANCE_PROGRAM`, `PREDICATE_PROGRAM` and the
  derive pins), and no served read's format changed (only the default
  agent's refine calls `scope`, and no pinned blob holds that kernel).
- **The mirrors deleted:** `wire::credentialed` sends `vos_wire`'s
  `ingress::Credentialed` under `Kind::Credentialed`;
  `credentialed_answer` decodes the node's `Response` exactly and
  answers `Answer::Refused(CredentialRefusal)` for the refusals it does
  not tell apart (`CREDENTIALED`, `PublicBody`, `CredentialedBody`,
  `LAST_REFUSAL` and the refusal bytes gone).
- **End to end** (`node/host/tests/served/credentialed.rs`,
  `the_device_librarys_proofs_are_admitted`): `SCOPE_VECTOR` from both
  `vos_device::scope` and `vos_wire`'s; on three nodes of a founded space
  the library's `path_query` bytes answered over the node's HTTP into a
  `PathKeeper`, its `prove_auth` proof's request admitted at a follower's
  ingress as it leaves the library, the poll's `login` answering
  `ctx.nullifier` equal to the proof's nullifier, the same request
  `Replayed`; 68 enrollments pushing the root out, the leader's answer
  decoding as `Answer::RootUnknown`, the keeper's refetch and a new proof
  admitted; an owner proof paying 20 from the row its owner digest
  claimed. Under 7.11's scope (the name's bytes alone) the vector
  differs, so the scope assertions would fail and ingress refuse the
  proof `Scope` [inferred].
- **The fuzz replay seeds** of `credentialed_decode` and
  `credential_verify_bytes` made again under 44 (`credential_ingress
  --seeds`); no other corpus held a 42 proof.
- **`node/SECURITY.md`** is 7.11's, its path leak taking this step's
  specifics (the timer, the moved root's spread, the `RootUnknown`
  refetch); the docs' scope lines say both widths and the SCALE name.
- **The rate bench and the verifier under 44:** 7.11's entry (quick
  sanity under another agent's load, not the gate).
- **Gates** [measured; 12 GiB scope, `nice -n 10`, 6 jobs, another
  agent's proving stress beside it]: the served `credentialed` 6 (the
  new one among them), `vos-device`'s 8, the wire's, `kernel
  constants::`; `just check` green at `057a0364` (exit 0, 1,638 passed in
  125 suites, no flake); `just test-proof` green, 579 passed in 50
  suites.

**Commits:** `5f8678fb` format 44 registered, 42 retired; `814caf3c` the
device library and the phone bench; `95950c51` session P2's record; this
record and the plan's text.

**Gates** [measured; 12 GiB scope, `nice -n 10`, 6 jobs, another agent's
runs at times]: `just check` at `11bef490` green through the formatting,
the docs, the venue rules, the no-std builds, the leak gates (the new
`seeded-masks` row among them), the kit, the guests, the fuzz replay, the
lints, the core crates (`vos-device`'s 8 among them) and `test-recair`;
in the agent crates `vos-checker`'s
`a_held_tcp_port_takes_no_listener_and_resets_what_connects` failed once
(`AddrInUse` rebinding its port, other agents' runs binding ports
beside it; untouched here) and passed 3 of 3 alone; the agent crates
rerun with `--no-fail-fast`, 699 passed in 53 suites, and `test-reads`
green. `just test-proof` green, 579 passed in 50 suites.

## Step 7.8b: the agent-side items and `blobs.lock`

Branch `s7/7.8b`, from vos-core `4a143e9f`: slice 6's carried items
outside `pvm/proof`'s chips (the plan's split, `slice-7-mobile.md` §7.8b;
the items `research/slice-6/quality-review.md`'s), in one commit with the
review's fixes after it, and the lock of every guest blob (L2).

| item | what |
|---|---|
| 3 | the service's `RegisterCode`, `AnchorCode` and `ControlCode` declared by one `codes!` macro, each with its `TryFrom<u32>` (the code back when it names none); jam-dev's `anchor_code` gone, `register_code` a `match` on the `TryFrom` |
| 4, guest half | nothing left: 7.1's `vos_anchor::venue::{expiry, fresh, aged, seen_expiry}` are the root-expiry and `seen_expiry_of` the item asked for, and `check-venue-rules` keeps the rule there |
| 17–19 | no `vos-anchor` or service piece: all three were recair's and the final verifier's, landed at 7.8a |
| 20, the service's piece | `#[repr(u8)]` tags: the verdict's private `Tag` (its order is not `item::Kind`'s, now said where it is defined), the control's `OpTag`, the storage's `keys::Prefix` (`CURSOR` and `GAS` keys of it); the bytes unchanged |
| 21 | `codec::{flag, option_u64}` and `Reader::{flag, option_u64}` in `vos-anchor`, used by the service's `SpaceRecord`; `ProgramId::decode_from` public in `vos-statement` (its `decode_program` gone), used by the service's `Config::decode`. The flag and pin codecs the item also named went with 7.1's rootless and `venue_bound` removals |
| 22 | the service's handlers return their code enums, cast once in `apply`; `From<AnchorRefusal> for AnchorCode` and `From<RegisterRefusal> for RegisterCode` (refine's `register_code` gone); `Outcome.kind: Option<Kind>`, its byte `u8::MAX` for none as before (`Kind::{encode_option, decode_option}`, shared with the verdict's refusal) |
| 23 | the guests' runtime (`src/bin/guest/runtime.rs`) holds the `entries!` macro (the `_start` trampolines, the same instructions, so refine stays at instruction 0 and the service's accumulate at 5), `Output`, the host calls as `Call` and `fetch`'s kinds as `FetchKind` (`#[repr(u64)]`), and `NONE`. The `vos-pvm-guest-rt` crate the item named for later, which would drop the service's dummy `heap-peak` feature, is not made |
| 24, the service's piece | refine split into `refine_register`, `refine_anchor`, `refine_control`; an accepted statement's id is the one `admit` computed, hashed again only for a refusal's outcome; `fetch_exact`, the one read `fetch` and the proof share |
| 25 | `Anchor::decode_from` (the service reads its item through it, no byte count of its own); `keys::anchor` and `keys::evidence` one `at_window`; `Evidence::decode` splits at `AnchorRecord::BYTES`; `RootKind::decode_from` through its `TryFrom`. Left: `pvm/codec/src/anchor.rs`'s offsets (Low in the review; the codec reaches the kernels) |
| 26 | `SpaceGenesis::version` dropped; the encoding writes `GENESIS_VERSION` as before, byte for byte; the anchor vectors unchanged |
| 27 | `final-verify.elf` has no `Anchors` mode: a mode byte 2 is a bad payload there, its digests zeros (`the_anchor_vectors_are_computed_on_the_jam_only_host_as_pinned` checks both programs); `final-verify-test.elf` computes the vectors. `vos-statement`'s `test-formats` enables `vos-anchor/vectors`, `pvm-guest` no longer does |
| 28 | the service's `natural` and `Operand::decode_input` gone: refine's arguments are `vos_wire::jam::RefineArgs::decode`, accumulate's `vos_pvm_program::read_nat`, its inputs `vos_wire::jam::AccumulateInput::decode`, and the operand `vos_wire`'s. Stricter: canonical naturals only; refine's arguments whole, the package's hash after the payload and nothing past it; an input in its exact layout, its work error one of the six Gray Paper 0.8.0 codes |
| 33 | `vos_pvm::refine_host::FetchKind`, Gray Paper 0.8.0's sixteen kinds: the JAM-only host's prices and its serving, and the accumulate host's `FETCH_INPUT(S)`, all through it |
| 64 | `Attest::weight` and `Attest::weighed` in `vos-wire`; the default agent's `attests_counted` and the testkit's `counted` gone, with the save and restore of them around a failed call |
| 65 | `Base::decoded`, exact, for `admin`'s and `closes`' row readers; exact decodes of the space and clock rows read through the step, a pending read, the served rows, a kernel's return, an installed record and a workflows' count. Left: the workflow record (`Workflow::decode`, versioned by its `format`), and `vos-sdk`'s `served`, exact already and in every kernel |
| 66 | the cut and close rows split into `keys/cuts.rs`; `window_of` for the five window-only parsers; `request_id` and `request_of`, the `RequestId` layout once. Of the test-only API the review named, `is_replicated` has a production user now (the checker), `closed_prefix` the reads' tests, and `moved` is gone |
| 67 | `AgentRoot.kind: RootKind`; `AgentPath` for the `(agent, salt, path)` tuple; `vos_tree`'s `EntryTag` enum for the `Entry` tag constants; `From<Attesting> for WorkflowState`. SCALE bytes unchanged |
| 69 | one guest workspace, `agent/programs` (the lockfile, the toolchain, the target configuration and the release profile), for the default agent, the representative and the credential actor, each built alone (`_build-program`) and its ELF under `agent/programs/target`; the window actor's forward-looking sentence and two unreflowed doc paragraphs fixed (`inputs.rs`'s was already) |
| L2 | `blobs.lock` (below) |

**`blobs.lock`:** the SHA-256 of 30 guest blobs, each ELF with its symbols
and relocations stripped (the toolchain's own `rust-objcopy`), written by
`just blobs-lock` and checked by `just check-blobs` at the end of
`check-no-std`: `final-verify.elf`, `final-verify-test.elf`,
`statement-service.elf`, the representative, the credential actor and the
25 test actors (the bins their workspace declares, so an ELF another
branch left in the target is not one). A set `CARGO_TARGET_DIR` is
refused, and a blob that cannot be hashed fails the check.
- **The venue guests** are built by `_venue-guest` with
  `--remap-path-prefix` for the checkout's root, `CARGO_HOME` and the
  toolchain's sysroot: before, `final-verify.elf` and
  `statement-service.elf` carried this machine's `$HOME` in 39–41 panic
  locations, so their bytes depended on the checkout and the machine.
- **Why stripped** [measured, a clone at another path built from clean]:
  cargo's `-C metadata` hashes a path dependency by its path relative to
  the workspace's root when it lies under it, else by its absolute path.
  The venue guests' workspace (the repository's) holds all their sources;
  the out-of-tree workspaces (`agent/test-actors`, `agent/programs`, the
  Wasm blob's) depend on `agent/sdk`, `agent/wire` and `pvm/…` outside
  their roots, so their symbol names hash the checkout's path. For the test
  actors, the representative and the credential actor only the symbol
  table differs (stripped, all 27 equal); the kernels' program ids, which
  read the code, never moved.
- **Left out, the code itself differing between checkouts:** the default
  agent's `.text` (`vos-agent.elf`; its `.rodata`, `.data` and schema
  equal) and both Wasm blobs (48,515 bytes differ, from the function
  table on), the items' order following the symbols' hashes. So the
  default agent's program hash depends on the checkout's path today. The
  levers, for the owner: build those workspaces from a fixed path, or
  bring their crates under one workspace root with their dependencies (the
  repository's), which the toolchain and the profiles now keep apart.

**What moved:**
- Every guest blob: the venue guests and
  the Wasm blobs with the runtime, the anchor and the statement changes and
  the remap; the agent programs with the wire and the workspace; the test
  actors' ELFs in their symbol tables (the wire's moved and new items),
  their code unchanged.
- No pinned value: `kernel constants::` passes as at `4a143e9f`
  (`WINDOW_PROGRAM`, `BALANCE_PROGRAM`, `PREDICATE_PROGRAM`, the derive pins).
- Behaviour, each deliberate: the service refuses non-canonical naturals
  and inexact arguments and inputs (item 28): a work error past 6 now drops
  its input, where the old decode recorded `FAILED + code`; no Gray Paper
  0.8.0 node gives one. A `Report` body of a root kind other than `Space`
  no longer decodes, where it decoded and was ignored; only the agent's own
  close step makes one. Rows with trailing bytes are corrupt where item 65
  reads them.

**The teammate's third drop:** the vendored `vos-anchor` (`SpaceGenesis`
without `version`, its encoding unchanged; `Anchor::decode_from`; the
codec's flag and option pieces) and `vos-statement` (`ProgramId::decode_from`;
the guest's `Anchors` mode in the test program alone; `test-formats`
enabling the vectors). The pallet's only code change: a `SpaceGenesis`
built without the field. The conformance vectors and the fixtures are
unchanged, and no pinned program id moved. `blobs.lock` is VOS's own: no
blob ships in the kit. `teammate-note.md`'s drop line says so.

### The review's fixes

One Opus review of the commit, no High; folded:
- **M1:** `check-blobs` hashed every ELF in the test actors' target, so one
  another branch left failed the check: the actors are now the bins
  `cargo metadata` lists; a set `CARGO_TARGET_DIR` is refused.
- **M2:** right: built from clean in a clone at another path, every blob
  but the venue guests differed. The lock hashes the ELFs stripped and
  leaves out the default agent and the Wasm blobs (above); the clone's
  clean build then checks it, 30 of 30.
- **L5:** the `_forbidden` rows read `agent/programs`'s whole workspace,
  the representative and the credential actor with the agent.
- **L6:** the installed record and the workflows' count decoded exactly.
- **L7:** the guest's doc says the mode is `test-formats`'s.
- **Nits:** `hostcall!`'s `($id) as u64`; `request_of` by `as_chunks`; a
  doc paragraph reflowed.
- Left: the six byte-to-enum tables as they are (each its crate's, two of
  them the guest's and the host's `FetchKind`); the `AgentPath`
  destructuring, whose renames are `Body::Closed`'s fields; refine's copy
  of the payload (`RefineArgs` owns it), a few hundred gas; L3 and L4,
  recorded above.

**Left:**
- **The owner's call, pending:** the default agent's and the final
  verifier's Wasm blobs' code depends on the checkout's path (above), so
  they are outside `blobs.lock`, and the default agent's program hash
  differs between checkouts. The levers: build those workspaces from a
  fixed path, or bring their crates under one workspace root with their
  dependencies.
- **Trim-paths, tried** [measured, branch `s7/repro-blobs`; two clean
  worktrees at paths of different lengths, each its own targets]: built
  as the recipes build them, the three differ raw and stripped, and no
  path is among their strings. What differs is order alone: the crate
  hashes in the symbol names (`vos_wire`, `vos_tree`, `vos_agent` itself,
  each outside `agent/programs`; `core` and `alloc` equal) order the items
  rustc sorts by symbol name, so four `drop_in_place` glues in the
  agent's `.text` trade places (2,489 bytes; every function's size, the
  other sections and the headers equal; no build id) and the Wasm blobs'
  functions likewise. Trim-paths (`-Ztrim-paths` with the profile's
  `trim-paths = "all"`), alone or with the venue guests' remap
  (checkout root, `$CARGO_HOME`), changes every crate hash (the profile
  is hashed) but not that they differ: the three still differ. It cannot
  fix it: cargo hashes a path dependency outside the workspace's root by
  its absolute path, whatever rustc's flags. Neither can a `-Cmetadata`
  in the flags (rustc joins every `-Cmetadata` with cargo's, it replaces
  none) nor `__CARGO_DEFAULT_LIB_METADATA` (one more seed beside the
  path: the agent still differs). Built through one fixed path instead
  (a symlink to each checkout, `--manifest-path` through it), the three
  are byte-identical, raw and stripped. So both levers fix it: a fixed
  build path, measured; one workspace root holding the crates and their
  dependencies, as the venue guests already reproduce unstripped. A
  fixed path shared by checkouts needs a lock against two building at
  once.
- `pvm/codec/src/anchor.rs`'s hand-computed offsets (item 25, Low; the
  codec reaches the kernels).
- The `vos-pvm-guest-rt` crate item 23 named for later, which would drop
  the statement service's dummy `heap-peak` feature.
- The workflow record's loose decode (item 65), versioned by its `format`.

**Gates** [measured; 12 GiB scope, `nice -n 10`, 6 jobs, another agent's
credential stress beside it]:
- **`just check`:** green at `dae8b822` (exit 0, 1,640 passed in 125
  suites): `check-blobs` among it (30 blobs), the conformance vectors'
  generator (`the_vectors_are_the_generators`, the vectors unchanged) and
  `check-kit`.
- **The fixtures:** `fixtures::the_fixtures_are_the_generators` alone,
  green (243 s): the fixtures unchanged.
- **`kernel constants::`:** green; no pinned program id moved.
- **`blobs.lock` reproduced:** `just check-blobs` in a clone at another
  path, built from clean: 30 of 30.

## The honest credential proof refused

Branch `s7/completeness`, from vos-core `7b78d9af`. 7.11's left item: one
honest format-42 proof in about 30,000 refused by the verifier.

**The cause** [measured]: the Stwo fork's SIMD `reduce_to_m31_simd`, which
reduces each word of a Blake2s-M31 leaf's or node's digest below p,
computed `M31::reduce`'s formula in 32-bit lanes, where
`v + (v >> 31) + 1` wraps for `v ≥ 2^32 − 2`: the prover's tree held
p − 1 and p where the verifier, reducing in 64 bits, recomputes 0 and 1.
A node with such a word on a queried path, about one word in 2^31, made
the recomputed root differ (`RootMismatch`). The kept proof's refusal is
this: its FRI layer 7 decommits a leaf of 4 M31s
(`0x52080a2a 0x5368d2ec 0x1b80dd5a 0x2826d36f`) whose digest's word 4 is
`0xffffffff`, and a verifier made to reduce as the SIMD prover did accepts
it. Not a race, not the masks' randomness, not FRI's folding: the seeded
build refuses the same seed every time.

**The fix:** the fork's `vos/simd-m31-reduce` (`9e9b4ff6`, on
`vos/grind-chunks`' `4cd1f83f`; not pushed) folds `v = hi·2^31 + lo` to
`lo + hi ≤ p + 1` and subtracts p once, canonical over the whole `u32`
range, with tests of the edges, windows of 2^16 values against
`M31::reduce`, and a leaf and a node whose raw digests reach `2^32 − 1`
and `2^32 − 2` built alike on the SIMD and CPU backends. The workspace,
the kit's, the Wasm blob's and runner's locks and the fuzz crate pin it.
VOS's own tests: `pcs::tests` (a SIMD-committed tree holding the leaf
verified by the CPU Merkle verifier; a SIMD node at the `2^32 − 2` word),
both refused on `4cd1f83f`; `credential/prove::a_digest_word_at_the_top_of_the_u32_range_verifies`
(seed 4033's auth proof, `RootMismatch` on `4cd1f83f`); and the
`credential_stress` example, which proves and verifies seeded statements
in volume and prints each failing seed.

**Before and after** [measured; `credential_stress`, 6 threads, `nice`,
other agents' runs on the machine]:

| pin | format | proofs (owner + auth) | refused |
|---|---|---|---|
| `4cd1f83f` | 42 | 60,000 (seeds 0–29,999) | 2 (auth 4033: trace tree; auth 25464: FRI layer 7) |
| `9e9b4ff6` | 42 | 180,000 (seeds 0–89,999, 4033 and 25464 among them) | 0 |
| `9e9b4ff6` | 44 | 20,000 (seeds 0–9,999) | 0 |

At the rate before the fix, 180,000 proofs would have held about six
refusals; none at 3× the volume that found two bounds the rate after it
below about one in 60,000 at 95% (`3 / 180,000`); the reduction, now
exact, leaves none.

**Other formats:** only the Blake2s-M31 stack reduces a digest: formats
42 and 44 and the device format 37 (registered, refused until its AIR and
channel exist; the device library's prover would have hit it on any
target, SIMD lanes being portable). Blake2s without the reduction (the
small test formats), Poseidon2-M31 (32, 35) and Blake2b-256 (28, 39) never
call it; the PoW grind reduces with `PackedM31::reduce_simd`, correct over
`u32`. The pinned credential roots and program ids are unchanged
(`prove::the_pinned_programs_are_the_circuits`).

**Left:** pushing `vos/simd-m31-reduce` before this pin reaches a shared
branch; Kreivo re-vendors the kit's lock after. The device spike
(`spikes/s7-device/harness`, at `c3ec9813`, its lock already behind the
workspace) needs the pin before a phone run of format 37. A committed
column lane equal to p (which `PackedM31` can hold: `-0`) would mismatch
the same way at a leaf; VOS's salts and FFTs never produce one, so it is
latent, noted for the fork.

**Review:** one Opus review: the reduction correct for every input and on
every `min` branch; no other prover/verifier reduction mismatch in the fork
or VOS. Folded: the fork's tests assert the raw digest words, a windowed
sweep; `pcs`'s comments timeless and raw words asserted; the harness's
refusals counted apart from failures to prove, 44's roots computed once,
its usage.

**Gates** [measured; 12 GiB scope, `nice -n 10`, 6 jobs, other agents'
runs on the machine]: the fork's `stwo` lib tests (306, `prover,parallel`)
and clippy; `just check` green at `87232c17` (exit 0, 1,630 passed in 122
suites); `just test-proof` green at `87232c17` (exit 0, 581 passed in 50
suites, `pcs::tests` among them); `just check` again with this record.

**Commits:** the fork's `9e9b4ff6` (`vos/simd-m31-reduce`); `87232c17` the
pin, the tests and the harness; this record.

## Step 7.13: the demo in s4

Branch `s7/7.13`, from vos-core `4a143e9f`; s4 on its `vos` branch (the
worktree `~/src/virto/s4-vos`), from `cee80d9`.

**Built in s4** (AGPL-3.0-or-later):
- **External facilities** (`s4-protocol`): the `s4.` namespace stays
  closed, another namespace's facility is admitted (`admits_facility`,
  `CapabilityError::UnregisteredFacility`); `STATE-MACHINES.md` says so.
- **`s4-server`**: `Server::facility(id, major)` offers one
  (`InvalidFacility` for `s4.` or a repeat); `Server::anonymous()` takes
  any public key as an identity for its connection alone
  (`Identity::anonymous()`): no session parked or resumed (a resume
  request gets a fresh id nothing keeps) and remembered grants stripped.
- **`s4-credential`** (`credential/`, outside s4's workspace on VOS's
  nightly, a `cdylib` with the `ffi` feature): the `vos.credential`
  facility on `vos-device`, `vos-api` and `vos-wire` at vos-core
  `4a143e9f` (no VOS library change was needed). Enroll pins the space,
  agents, methods, guards and scopes in a chrome form and shows the two
  digests in another; sign-in names the method and its `once` guard; pay
  proves `transfer` with the payee and amount the chrome form returned,
  the server's only a pre-fill. The path and the node's time come over
  `vos-api` connections of their own, each under a fresh key and the
  session's verified host key. Values cross the C ABI as CBOR.
- **The client**: external facilities in trusted chrome (a grant prompt per
  connection, then a form per call), offered only on anonymous
  connections under a key drawn for the connection (`Auth::Ephemeral`),
  with no resume and no remembered grant; `libs4_credential.so` loaded by
  `libloading`. On Android, `KeystoreBridge` (a non-exportable HMAC key in
  StrongBox when present, biometric or PIN at each use, the output a
  `byte[]` zeroed after the copy) and the YubiKey's hmac-secret through
  YubiKit's `HmacSecretExtension` (user verification, rpId `vos.device`);
  the facility reports itself unsupported below API 30. `-Ps4Vos` builds
  the debug APK with the credential library (arm64).

**Built in VOS:**
- **The gateway's s4 app** (`node/gateway/src/demo.rs`, the `ssh` feature):
  three screens (enroll, sign in, pay) against the `purses` ledger and the
  credential actor, and the `vos.gateway` host service relaying a
  facility's `Credentialed` request only when it names the demo's agent
  and the screen's instance and method; the app key sends `claim` and
  `claim_row` for invited members without a key.
- **`node/gateway/demo`** (outside the workspace, s4's crates asking a
  newer Rust): a local founded space and its gateway (`LocalSpace`), the
  `vos-gateway-demo` binary for the phone run (stdin commands `invite`,
  `mint`, `balance`; the host key's seed kept under `--data`), and the
  end-to-end test with a headless s4 client.
- **`node/SECURITY.md`**: the demo's SSH surface.

**Tests:** s4's `anonymous` e2e (an external facility reaching a client
that grants it; no resume or remembered grant when anonymous; `s4.` or a
repeat refused), the credential crate's 7 unit and 3 integration tests
(enroll, sign in and pay as the chrome confirmed; the API channel's host
key; nothing proved before enrollment), the client's facility tests; in
VOS `enroll_sign_in_and_pay_through_the_gateways_ssh_port` (the
document's fields say 999 to mallory, the chrome confirms 20 to shop:
shop gets 20, mallory nothing) and
`a_request_naming_another_method_never_reaches_the_node`, in
`just test-gateway-ssh`.

**Deviations:**
- s4 does not build on VOS's nightly (`typed-index-collections`, Slint)
  and VOS's crates not on s4's stable, so the facility is a `cdylib` the
  client loads, not a crate it links.
- The enrollment file keeps the member digest beside the handle (0600),
  so a path can be asked for without the secret.
- The demo crate sits outside VOS's workspace.

**The review** (Opus, read-only) found three high, nine medium and eight
low; folded:
- H1: the path is kept per enrollment for the process, refreshed on a
  schedule of its own (a drawn first delay, a spread, at most once in 30
  s), each fetch and each time read on its own connection.
- H2: the digests shown in the device's chrome; the gateway's screen no
  longer shows them, and the e2e reads them from the chrome.
- H3, in part: a path is used only when its root is one the root polls saw;
  a gateway marking an address's polls is left to node-signed roots, as
  `SECURITY.md` says.
- M1: a `once` call with arguments refused; M2, in part: an owner guard is
  pinned only for `transfer`; M3: names shown are ASCII
  `[A-Za-z0-9._-]`; M4: one call at a time per session, a form answers
  only after 600 ms on screen and never from Enter; M5: the same payment
  within its expiry answers the same request; M6: a node time more than
  five minutes from the device's refused; M7: external facilities only on
  anonymous connections; M8: `refresh` rate-limited and spread; M9: an
  enrollment refused when another origin holds the handle or space.
- L2 (rows 28), L3's first copy (zeroizing), L4 (host key kept), L6 (a
  form's values reset), L7 (the chrome's lifetime documented), L8
  (`SECURITY.md`).

Left: L1 (a cancelled call's form stays until answered; the proof is
dropped), L3's PIN in the `Editable` and YubiKit's own copies, L5 (no way
to forget an enrollment), M2's `once` label still the gateway's word at
enrollment, H3's marked polls.

**Gates** [measured; 12 GiB scope, `nice -n 10`, 4 jobs]: VOS `just
check` green at `4dbc590f` (exit 0, 1,638 passed in 125 suites) and
`just test-gateway-ssh` green (the gateway's 10, the SSH port's 3, the
demo's 2); s4 `just ci` green at `57fbab9` (exit 0, the `vos` step among
its gates). The first s4 run failed `deny` on two advisories new to the
database (RUSTSEC-2026-0414 in `pulldown-cmark`, RUSTSEC-2026-0424 in
`wasmtime`), not this step's; `57fbab9` takes their fixed releases. The
debug APK builds with `libs4_credential.so` for arm64.

**PG3 not run.** The phone was not attached, and every flow needs the
owner's fingerprint or PIN (Keystore at each use). What the owner does is
in this step's report.

**Commits:** s4 `9b920d0` external namespaces; `e8f9c16` the server's
facilities and anonymous connections; `bd79bb8` `s4-credential`;
`76bf809` the client; `bc1534b` and `6f60229` the review's folds;
`57fbab9` the advisories' updates. VOS `504f4b47` the gateway's screens;
`fcbf6f45` the demo and its e2e; `4dbc590f` the review's folds (s4 pinned
at `6f60229e`); this record.
