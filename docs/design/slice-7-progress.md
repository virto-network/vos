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
