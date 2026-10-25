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

**M4:** `prune` makes any aged unfinished job dead (its proof unheld) and
removes the jobs of an agent the node no longer replicates; each
unfinished job's kernel is held under `NODE_AGENT`, fetched from the
replicas when absent, and a statement whose kernel never arrives within
the worker's patience is refused (`NO_PROGRAM`), the step proving another
job meanwhile.

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
without its witness. Worker: jobs aging out and going with their agent,
a rootless record making no job; a kernel held and one never fetched
refused; a stop mid-proof counted only when the node was not stopping;
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
