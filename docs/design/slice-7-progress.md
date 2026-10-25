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

### 7.0b: the passkey PRF on the gate device

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
