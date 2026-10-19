# Slice 6: masking, and statements on chain

Plan, draft 4, final for commit. It takes the owner's decisions
(2026-10-19) and the handoff design of the spaces pallet
(`spaces-pallet.md`), after Fable's reviews of drafts 1 and 3
(`research/slice-6/plan1-review.md`, `plan3-review.md`).
- **The architecture** is `proving.md` (draft 5), `recursion-air.md`
  (draft 2) and the slice's design round on roots and anchors, folded into
  this plan's pins (below) with Fable's review of it. The research behind
  them moves to `research/slice-6/` at 6.0d:
  - `spike6a-mask-wrap.md`: the real wrap masked under variant (c), measured;
  - `spike6b-masked-bits.md` (and its table): the security tool's (c) terms,
    the candidate shapes;
  - `spike6c-kreivo.md`: the statement verifier linked into a real Kreivo
    runtime, benchmarked;
  - `design-roots.md` and `design-roots-review.md` (Fable): space identity,
    windows, roots, anchors, `&self` reads, the prover worker;
  - `external.md`: Kreivo, Stwo upstream and zero knowledge, JAM;
  - `context.md`: the work inventory and the stale statements;
  - `spaces-pallet-research.md`: pallet-communities, pallet-pass and the
    shape of a spaces pallet in Kreivo.
- **The spaces pallet's design** (`docs/design/spaces-pallet.md`, from
  6.16) is the handoff to the Kreivo teammate who builds it. Slice 6 writes
  no pallet code.
- **This slice builds `proving.md`'s M2 and M3:**
  - **M2:** the final wrap masked, under a new format, generic over its
    component set and channel so that slice 7's device proofs reuse it;
  - **M3:** statements that read a space's state at an anchored window
    cut, proved by a prover worker, judged by a JAM statements service;
    for Kreivo, the design of its spaces pallet, the verifier kit and the
    node's client, tested against a mock of the designed interface;
  - the items slice 5 carried here (`slice-5-progress.md`, "Carried out of
    slice 5"), each placed in a step below.
- **Slice 7 is mobile.** The Clerk across spaces
  (`clerk-across-spaces.md`, the Clerk's draft renamed at 6.0d) follows this
  slice.
- **Its home in the repository:** `docs/design/slice-6-on-chain.md`, with
  `slice-6-progress.md` beside it [proposed].

Tags: [measured] by a spike or a step; [model] by the security tool or a
fit; [est] arithmetic on measured numbers, not run; [decided] the owner's;
[proposed] open to review.

## Changes from draft 3

Fable's review of draft 3 (`plan3-review.md`), every finding folded in,
here and in `spaces-pallet.md`:
1. **Registration signs its `start_window`** (pin D, design §3 and §6.2,
   `register_digest`, 6.10's golden vectors), bounded by the venue's time;
   G1 refuses the resubmission.
2. **A spend budget per space and window** in `ChargeSpaceFee::validate`,
   covering the fee and the deposit, with `set_budget` (call 10) and G13:
   a compromised authority cannot drain the sovereign account.
3. **`WindowInFuture` is waited out and resubmitted, never skipped;** the
   client reads the venue's time before anchoring; 15 done, 17–18 dead
   (design §9, 6.17b, G4).
4. **`AnchorRecord` stores its signer, `Evidence` both signers;** `resume`
   needs both keys gone (G5's two-key case).
5. **The vectors pin deposits exactly and fees by sign only;** G14–G18
   cover the calls G1–G12 left out; the mock's bytes come from codec
   derives (6.17).
6. **The design is handed over at this commit,** with a build order (its
   §0.1, a stub `Venue` first); the kit at 6.16, the vectors at 6.17; A1
   is "name the teammate".
7. **Minors:** the format checked before the program in `submit`;
   `Record` defined, and a payer other than the statement's space allowed;
   `remove_authority`'s providers, `add_authority`'s update,
   `set_status`'s unblock, `BadClock` before the origin and "no
   compile-time metadata" in the design; 6.17's stale line removed;
   decision 11's repeat exception; the two-sided rule in the design;
   6.17b's `vosx space venue` tooling; 6.15 marked F.
8. **The deferred Kreivo gates** listed in M3b's acceptance, and the
   `kreivo` venue unselectable in production configuration until they
   pass.

## Changes from draft 2

- **The owner's decisions taken** (2026-10-19), all fifteen, moved to
  "Taken by the owner": 1–8 as recommended; 9–12 folded into the spaces
  pallet's design as its defaults; 11 a refundable deposit, not the
  recommended gas tank; 12 redirected to a general spaces pallet with a
  sovereign account and an authorities map; 13 the whole code-quality rest
  in 6.22 (each item listed there); 14 and 15 as recommended.
- **Decision 2's rule** in pin D and wherever a deadline arises (6.17,
  6.18, 6.19): time between parties is the venue's chain time, never a
  window number or the space's clock; and the latency across spaces
  explained (pin D).
- **Pin D:** the open window cannot be anchored (`w < now_w`); the
  controller an `AccountId`; the sovereign account and the authorities
  map, per `spaces-pallet.md`.
- **Kreivo is design and kit only** (decision 12): 6.16 is the verifier
  kit and the design committed; 6.17 the reference mock and the
  conformance vectors G1–G18; 6.17b the client against the mock; no pallet
  code; the weights, benchmarks and fees are the teammate's; 6.21's
  on-chain leg runs on the JAM service, the Kreivo leg against the mock,
  and on a dev chain only when the teammate's pallet exists. The design's
  §13 questions stay open in the design, not blocking slice 6.
- **6.9** takes decision 3; **6.0e** probes with a stock call.
- **Estimates:** M3b 4–6 weeks; 6.22 3.5–5 with the slice-5 rest; the
  slice 32–49 engineer-weeks; the critical path 16–26 weeks.

## Changes from draft 1

Each of the review's findings, and where it landed:
- **D1 (blocker), the node's Kreivo client:** a new step, 6.17b
  (`node/venue/kreivo`), a probe, 6.0e, and a new owner decision, 12
  (Kreivo accounts, funding, key custody). 6.17b precedes 6.21; with 6.20
  now counted, the critical path is 14–24 weeks, or 16–26 when the Kreivo
  track shares its implementer with M3a (Estimates); review latency is
  outside both.
- **A1, the FRI mask:** 8 columns, no production rank check, settled by
  the evidence (pins A and C); R3's check survives as a test on the small
  circuit; 6.0c is dropped.
- **A2, leakage gate 2:** redefined as witness indistinguishability, with
  its statistical power stated (6.6).
- **A3:** 6.2 recomputes the masked security shape from the built
  components.
- **C1:** the representative's leader returns the paths as a pair message,
  `Closed { w, rep_root, paths }` (pin E, 6.14), with a leader-change test.
- **C2:** a rootless statement's `Seen` entry never expires, at Kreivo and
  at the JAM service (pin F, 6.16, 6.19; decision 10).
- **D2:** the fees decision (11) reframed with Kreivo's existing
  `SkipCheckIfFeeless` and gas tanks, a refunded deposit, and the cost of
  each.
- **E1:** 6.0b decides by reading Gray Paper 0.8.0 whether the JAM
  service takes the proof in the work item's payload or as a preimage.
- **Minors:** per-component mask levels (A5); the Stwo-side facts the
  format pins (A6); the seam's build check without dev edges (A4, F4);
  why 40 is retired (B1); the verifier's constants against the registry
  (B2); a request re-cut when its window is not closed (C3); the model
  venue's migration range (C4); the precompiles' root kind (C5); the
  anchor crate's codec (C6); the two-sided rule where the pallet reads it
  (C7); an M3b acceptance (D3); the anchor signer checked in accumulate
  (E2); the second JAM service's tooling (E3); 6.21's JAM leg on the
  JAM-only host (E4); 6.5 marked F (F1); 6.15's signature (F2); 6.20 on
  the critical path (F3); 6.12's first test written first (G).
- **The owner decisions reordered** by when they block, and renumbered:
  draft 1's 8 and 9 are 3 and 4, its 3–7 are 5–9, the new Kreivo-accounts
  decision is 12, and its 12–14 are 13–15.

## Goals

1. **The final proof is masked.** Format 39 (pin A) proves the wrap of
   any statement:
   - at most 4.5 GiB of heap and 8 GiB of process peak, at most 15 s on a
     quiet machine (9–12 s with packed salts [est]);
   - verified in at most 200M JAM gas on the JAM-only host, with a target
     of 125M (about 98M expected with the fixed-layout decode [est]); at
     most 50M Wasm instructions; at most 170 KB;
   - 146 conjectured and 82 proven bits [model], with Fable's check of
     the terms;
   - the leakage gates 1–7 and the soundness gates 1–10 pass;
   - format 32, `H_fold`, every leaf-circuit hash and every program id
     unchanged, byte for byte.
2. **Statements read state.** An `#[attestable] fn f(&self, …)` reads
   committed rows at an anchored window cut, verifies them up to the space
   root, and states its `#[public]` arguments and that root in its
   io-hash. The record carries the statement's parts. The window kernel
   is restated: rooted, its anchors out of its output.
3. **Venues judge them.**
   - **JAM:** a statements service judges masked statements on the
     JAM-only host and on a PolkaJam testnet: refine at most 150M gas a
     statement, accumulate at most 2M gas a report. It is the slice's
     on-chain venue.
   - **Kreivo, design and kit:** the spaces pallet's design handed to the
     Kreivo teammate; the verifier crates packaged for vendoring with a
     sync check; conformance vectors G1–G18 generated from our fixtures; a
     reference mock of the designed interface that passes them; the node's
     Kreivo client passing them through the mock. The Kreivo leg on a
     chain runs when the teammate's pallet exists; it is not a gate of
     this slice.
   - Every venue judges every golden fixture alike.
   - The node reaches each venue through a `VenueClient`: its
     representative anchors and its worker submits; on Kreivo with one
     sr25519 authority key a node, the space's sovereign account paying.
4. **A prover worker** proves every anchored attest of its agents and
   submits it once: idempotent by statement id, keeping up with the window
   cadence at the default length (gate in 6.18). The program ids, `H_fold`
   and the wrap's root are repository constants, reproduced under both
   feature sets and on aarch64.
5. **The carried items closed:** the recursion AIR's forgery gates,
   panic-freedom by construction with fuzzing in CI, the reproducibility
   gate, Kreivo's dependency path (the kit), format 36, the adversarial
   fixtures, the code-quality rest from slice 5 and
   the venue binding (F2).

**No value rides on a proof in this slice:** the external audit comes
first (decision 14).

## What exists at the start

- **vos-core** at `31b7938e` (slice 5 accepted). The Stwo pin is
  olanod/stwo `ab294189` (`vos/wrap`).
- **Spike branches** (local, never pushed), whose code steps may take:
  - `spike/s6-mask` in `~/src/virto/stwo-s6-mask` (the masking
    prototype cherry-picked onto `vos/wrap`, salts at 8: `7379502`,
    `1c06864`) and in `.worktrees/s6-mask` (`c95b46c9`, `5227bf6c`): the
    masked AIR variant, prover, no_std verifier, R1 and R3 on the real
    wrap, the costs;
  - `spike/s6-bits` (`1b76b028`): the security tool's (c) terms,
    `MASKED_WRAP_REFERENCE`, the candidate grid;
  - `spike/s6-verifier` in `~/src/virto/kreivo-s6-spike` (`a7370f1`, on
    Kreivo master `87f8728`, stable2606-2): `pallet-vos-verifier` at index
    90, the fixture dumper, the benchmarks, the in-Wasm mutation sweep.
- **Measured by those spikes:** the masked wrap at blowup 32 and 24
  queries: 3.45 GiB of heap, 11.6–15 s, 160–163 KB, 115.8–118.7M JAM gas
  (decode 19.9M), 45.2M Wasm instructions; R1 and R3 in 16–39 ms; every
  tamper refused by an error. The unmasked verifier in Kreivo's runtime:
  +75.7 KiB compressed, 3.99 ms ref_time, about 20 proofs a block by
  proof_size on one core.

## How every step runs

- **A brief per step,** written when the step starts from this plan and
  the design docs. An implementing agent works from it alone.
- **Reviews:**
  - an Opus review of every step's diff;
  - Fable as well for the steps marked **F**: soundness, protocol and
    state-layout changes;
  - a step's review findings are folded before the next step builds on
    it;
  - review latency is not in the calendar estimates.
- **Gates:**
  - `just check` per step;
  - at each milestone's end, `just ci-full` (`ci`, `test-proof` with the
    leakage tests at their medium N, `test-bench-proof`, and `just fuzz`
    a minute a target) and the checker loop; the masked wrap's rows
    measured are read from `test-proof`'s own runs, no window proved
    again for them;
  - at the slice's end, `just slice-gate` (`ci-full`'s with the leakage
    tests at their full N and `just fuzz` five minutes a target) and the
    checker loop;
  - `just e2e-chain` (6.21) at acceptance, outside the gates: it needs
    PolkaJam's binaries.
- **Test tiers:**
  - the masked wrap's structure and tamper tests run on the generic small
    masked circuit (log ≤ 12) in `just check`;
  - the real masked wrap runs in `test-proof`, under `systemd-run` at 16
    GiB;
  - the statistical leakage tests run at small N in `just check`, at a
    medium N in `test-proof` and at full N in `slice-gate` (6.6).
- **Fixtures** come from the generator (`pvm/proof/tests/kernel/fixtures.rs`),
  regenerated by the step that changes them; masked fixtures through the
  seeded test seam (pin C).
- **Rules:**
  - commit on `vos-core` and never rewrite what is on origin; push after
    reviewed milestones;
  - **the Stwo fork:** reviewed branches may be pushed to olanod/stwo,
    each push after a Fable review of the fork change; never force-pushed.
    M2 needs no fork change (spike 6a used the fork's public API only);
    a fork change found by 6.7's audit follows this rule;
  - **Kreivo:** slice 6 writes no code in Kreivo's repository and no
    pallet, not even a test fixture; the teammate vendors the kit and
    builds the pallet from the design. The spike branch stays local;
  - **Rust:** no nightly feature in the source; stable for x86 and
    wasm32; the JAM builds on the pinned nightly with build-std; the
    vendored verifier stack builds on Kreivo's stable toolchain;
  - comments are timeless; no `#[ignore]`; no Co-Authored-By;
  - heavy runs under `systemd-run --user --scope -q -p MemoryMax=… -p MemorySwapMax=0`;
  - kill processes only by PID;
  - fix pre-existing failures that are hit.
- **Every measured number** in a step's log is tagged and lands in
  `slice-6-progress.md`.

## The pins

Specs the steps implement. Each is [decided on the evidence] unless
tagged; an owner decision it rests on is named.

### Pin A: format 39, the masked final wrap

| field | value |
|---|---|
| number | **39**. 38 stays unassigned (A.6's "a number no format holds"); **40**, spike 6a's blowup-64 shape, joins `RETIRED` though never registered, so no later format takes a number a measured proof once carried |
| kind, channel, encoding | `Wrap`; Blake2b-256 trees and channel; `Lossless` |
| proof bytes | a fixed layout (6.4), not postcard: a new `Format` field `bytes: ProofBytes::{Postcard, FixedLayout}`, 28 `Postcard` |
| parameters | log blowup 5, 24 queries, PoW 26, interaction PoW 8, fold step 3, log last layer 6, affine DEEP batching |
| floors, counts | 100 / 80; **146 / 82 (82.70)** [model, spike 6b]; 23 queries is the least that clears 80 (80.84) |
| status | `Reserved` at 6.1, `Admitted` at 6.4 |
| log sizes | `[14, 15, 11]` (`p2`, `qm31`, `h8`), as format 28 |
| AIR levels | each component's masked columns at its own n_c + 1: `p2` 15, `qm31` 16, `h8` 12, lifted (`MASKED_LOG_CONSTRAINT_EXPANSION = 2`; m + 1 = 16 is the tallest's); the composition's 4 coordinate columns committed whole at m+2 = 17, **never split**, sampled at π(z); the lifting height 22 |
| randomizer | h = 256 a column (`log_mask_rows = 8`): `f' = f + v_H·r`, deg r < h. Static checks: h ≥ 2(4\|O\| + q(\|O\|+1)) = 160 at q = 24, \|O\| ≤ 2; h ≤ N/4 for every component (h8: 512); h ≤ 2N/3 |
| salts | 8 M31 columns (248 bits) on each non-preprocessed tree (main, interaction, composition), at the lifting height; the preprocessed tree unsalted and unmasked |
| FRI mask R | **8** uniform base columns at level 17 in the composition tree, sampled at z, committed before z and before the DEEP coefficients. Eight independent QM31 coefficients span M31^4 unless an 8×4 matrix has rank < 4, about p^-5 ≈ 2^-155, so no prover check is needed; 4 columns would need a rank check failing about 2^-31 an attempt, a retry no production proof exercises, for a saving of about 64 MiB, 384 B and under 1% of gas [est] |
| blinding (R2) | 4 main columns per component, written after the body; one `BlindRelation` (`relation!(_, 1)`), drawn right after `Gate`, used by nothing else; one fraction a row a component; `b_c` nonzero on one row (r0, r1, −(r0+r1)); `claimed_c = true_c + r_c/(1 − z_B)` |
| tree widths | preprocessed 57, main 381 (373 + 8 salts), interaction 48 (40 + 8), composition 20 (4 + 8 + 8) |
| preprocessed root | equal to format 28's `PREPROCESSED_ROOT` [measured: columns at n+1 under blowup 32 are format 28's at n+6], pinned anyway by its own test |
| who accepts it | production venues accept {39}; 28 only under a `test-formats` feature and the model venue's test policy |

### Pin B: the masked transcript

In this order, prover and verifier (spike 6a §1):
1. the header, at format 39's number and configuration;
2. the preprocessed root (columns at n+1, unsalted);
3. the main root: each component's columns, then its 4 blinding columns,
   all masked, then the 8 salts;
4. the 24 public words; the interaction PoW (8 bits);
5. the `Gate` relation; then `BlindRelation`;
6. the blinded claimed sums; the interaction root (masked, 8 salts);
7. the composition coefficient;
8. the composition tree: the whole composition (4 columns at 17), R (8
   columns at 17), 8 salts;
9. the OODS point z: each component's masks sampled at its own level
   n_c + 1, the composition at π(z), R at z;
10. `prove_values`: the affine DEEP coefficients drawn after every
    commitment and every sample is mixed; FRI; the PoW; the queries.

The verifier never calls `stwo::core::verifier::verify` (its
`COMPOSITION_LOG_SPLIT` is hardcoded, DIVERGENCE-004): it runs over
`CommitmentSchemeVerifier::{commit, verify_values}` and the components'
public API, and takes the batching and every pin from the format, never
from the proof.

### Pin C: the prover's randomness (R1, R3, R4)

- **R4, hedged:** ChaCha20 seeded with
  `BLAKE2b-256("vos/mask/seed/v1" ‖ 32 OS bytes ‖ witness digest ‖ attempt as u32 LE)`;
  the witness digest is `BLAKE2b-256("vos/mask/witness/v1" ‖ the
  statement ‖ each main column's BLAKE2b-256)`: the statement's words (the
  format's number, its configuration, masking and interaction PoW, its
  channel's pinned tag, the log sizes) and the public values, then the
  unmasked main columns in commitment order, every private value of the
  witness among them, whatever the component set; so one witness proved
  under two formats or channels from a replayed OS state never reuses a
  mask [built at 6.3, the statement bound at its review; proposed first as
  the root node's proof bytes and output preimage, which only the wrap
  has; the channel bound by its type's name until M2, whose text the
  compiler does not promise]. Every mask, salt,
  R column and blinding value is drawn from it.
- **R1:** for every column class (level, quotient lift, offset set), the
  randomizer's revealed functionals (4 an OODS point, the decommitments,
  the composition's shifted reads) have full row rank over M31.
- **On R1's failure,** the prover re-randomizes every mask and retries,
  at most 8 attempts, then returns `ProveError::MaskRank`. It never fired
  at 80 revealed rows against h = 256 [measured, about 30 transcripts];
  it is the completeness guard the zero-knowledge argument rests on, and
  its refusal at h = 64 is a test.
- **R3, under affine batching,** is met by construction: R has 8 columns
  (pin A), so its DEEP coefficients span M31^4 except with probability
  about 2^-155. The production prover has no R3 check and no R3 retry.
  `fri_mask_coefficients_independent` (spike 6a) stays as a test over the
  generic small circuit, with 4- and 8-column masks, so the argument is
  exercised: at 4 columns it finds the singular draws a forced coefficient
  plants. **Why nothing more is needed:** R is witness-independent, so the
  simulator draws it as the prover does; with rank-4 coefficients the real
  and the simulated batches differ by an R-quotient (a function vanishing
  at z and at every query), which R's quotients reach, so the two batches
  have one distribution and FRI's whole transcript, its unsalted layer
  trees included, follows. No rank condition on R's own revealed
  functionals is needed, and no check runs.
- **A retry leaks nothing:** whether a transcript passes R1 is a function
  of public coins and the format, not the witness, so the conditioning is
  a public event a simulator reproduces.
- **Generic:** R1, the R3 test and the masking take the component set and
  the `MerkleChannel` as parameters; nothing names the wrap.
- **The test seams,** both under `cfg(feature = "seeded-masks")` alone:
  `MaskRng::Seeded(u64)` (the production default is `MaskRng::default()`,
  `Os`, and nothing else selects a variant), and
  `masked::prove_masked_unchecked`, the prover without its out-of-domain
  check, which hands the verifier a forced proof. No build reaches either
  from production code.
  **The build check** (in `just check`, beside `check-no-faults`):
  `cargo tree -e features,no-dev -i vos-pvm-recair` for each production
  binary (`vos-cli`, the agent, the node with `prover`) shows no
  `seeded-masks`, normal and build edges only (the fixture generator's dev
  edge enables it legitimately); and `debug-internals` does not imply
  `seeded-masks`.

### Pin D: spaces, windows, roots, anchors (`vos-anchor`)

Rests on decisions 1, 2, 5, 6, 7, 11 and 12. The Kreivo side of it is
`spaces-pallet.md`'s.

```rust
// pvm/proof/anchor (vos-anchor): no_std, depends on blake2 only.
pub type NodeNumber = u8;                    // one byte in SCALE(genesis)
pub struct SpaceGenesis {
    pub version: u8,                         // 1
    pub nodes: Vec<(NodeNumber, [u8; 32])>,  // founding node keys, numbers strictly ascending: the first anchor keys
    pub clock: WindowClock,                  // frozen: a space with another clock is another space
    pub time: u64,                           // ms since the Unix epoch, the founder's clock
    pub nonce: [u8; 16],
}
pub struct WindowClock { pub origin_ms: u64, pub length_ms: u64 }
pub struct SpaceId(pub [u8; 32]);            // SpaceId::NONE = zero, rootless statements
pub struct VenueId(pub [u8; 32]);
#[repr(u8)] pub enum RootKind { Space = 0 }  // 1 reserved: Poseidon2 (slice 7); unknown: refused at decode
pub struct RootRead { pub kind: RootKind, pub space: SpaceId, pub window: u64, pub root: [u8; 32] }
pub struct Anchor { pub space: SpaceId, pub window: u64, pub kind: RootKind, pub root: [u8; 32],
                    pub signer: [u8; 32], pub signature: [u8; 64] }
pub struct Migrate { pub space: SpaceId, pub from: VenueId, pub to: VenueId, pub from_window: u64 }
```

| item | definition |
|---|---|
| `SpaceId` | `BLAKE2b-256("vos/space/id" ‖ SCALE(genesis))`; `SCALE(genesis)` is the version, a compact count of nodes, each its number (1 byte) and key (32), the clock's origin and length, the time (each 8, LE) and the nonce (16); a decode refuses no node and numbers not strictly ascending |
| founding keys | 1 to 16 (`MAX_FOUNDING_KEYS`, Kreivo's `MaxAnchorKeys`): `vos space up` founds no other, a venue registers no other; the decode reads any count |
| a space without a genesis | `SpaceId::NONE`: its agents record no space at their first install, for good, run no cuts and refuse `attest_at_cut`. So a space is founded before its first agent: `vos space up` on a stopped founding node holding no agent, then `<space file>.genesis` copied beside every node's space file and the nodes restarted. A node refuses an agent's record naming another space than its own |
| window of time t | `w = ⌊(t − origin_ms) / length_ms⌋`; t < origin_ms has none |
| boundary | `B_w = origin_ms + (w+1)·length_ms` |
| length | `length_ms` ∈ [120,000, 3,600,000], default 600,000 (decision 2); the venue refuses another at registration |
| `cut(w)` | the agent's state version before the first applied result with time ≥ `B_w`: a result timed t, after the agent's batch-time mark p, records it for every w with p < `B_w` ≤ t, once the record its first install wrote names a space (the install itself cuts nothing, so only windows past the agent's first install are cut); of more than `MAX_CUTS` (32, a consensus constant) such windows, the newest 32 alone, the older never cut. A recording whose first window is w deletes the `cut`, `moved` and `closed` rows of every window before `w − CUT_KEEP`, `CUT_KEEP = 2 + RECUTS = 4` (a consensus constant; decided in 6.14): a read lives from its window w₀ to its deadline `B_{w₀+3}`, so no row older serves one, and a replica down longer than that skips those cuts, its reads re-cut or ended `NotClosed` as everyone's |
| the representative | the agent `agent_id(first founding node, 0)`: serial 0, which no node gives an agent otherwise; created on that node (`Node::create_representative`), its actor `vos-representative` (`agent/representative`) installed at instance 0 with the representative's clock. Its replicas are founding nodes, whose keys a venue registers as anchor keys: the node refuses another in its creation and its replacements |
| agent root | the vos-tree root over the agent's committed rows `0x03 ‖ instance ‖ tag ‖ transform ‖ key' → value` (pin E); empty: `H("vos/tree/empty")` |
| representative's rows | a `CommittedMap<RepKey, [u8; 32]>`, `RepKey = agent (4, BE) ‖ kind (1) ‖ w (8, BE)`, the value the agent's root at `cut(w)`; kind 0 is pin E's Blake2b tree; an agent's rows older than `w − 2` deleted by its report of w. Beside it a plain table `asked`, `w (8, BE) ‖ agent (4, BE)`, of the agents whose reads wait on w's close; an agent's asks go with its rows, so no report touches another agent's |
| representative's clock | `(origin_ms + D, length_ms)`, `D = min(length_ms / 5, 120,000)`: its own `cut_rep(w)` at `B_w + D` is the close of w |
| space root | `S_w = BLAKE2b-256("vos/space/v1" ‖ space (32) ‖ w (8, LE) ‖ A_rep (32))`, `A_rep` the representative's agent root at `cut_rep(w)` |
| `VenueId` | Kreivo: its genesis hash; JAM: `BLAKE2b-256("vos/venue/jam" ‖ JAM genesis hash ‖ service id (4, LE))` |
| anchor digest | `BLAKE2b-256("vos/anchor/v1" ‖ venue ‖ space ‖ w (8, LE) ‖ kind (1) ‖ root)`, ed25519 by a registered anchor key |
| registration | a founding key's ed25519 signature over `BLAKE2b-256("vos/space/register" ‖ venue ‖ space ‖ controller (32) ‖ start_window (8, LE))`; the venue takes the genesis itself and computes the id, so it learns the clock and the founding keys from the hash. The first window the space anchors at the venue is signed, so nobody who sees a registration can resubmit it with a start that keeps the space from ever anchoring; the venue also bounds it, `now_w − MaxRootAge / length_ms ≤ start_window ≤ now_w + 1` by its own time |
| controller | an `AccountId` (32 bytes) at each venue: a person, a multisig, a pass account or a community account; it rotates the authorities and anchor keys and migrates the space. Anchor-key rotation is not yet supported on VOS's side: a node signs anchors with its node key, and only founding nodes replicate the representative (6.14), so a key the controller adds is used by no node until 6.14b |
| sovereign account | on Kreivo, `PalletId(*b"kv/space").into_sub_account_truncating(space)` (`b"modl" ‖ b"kv/space" ‖ space[0..20]`): derivable from the genesis before registration, so the founder funds it first; it holds the registration deposit and pays every fee and `submit` deposit of the space's authorities, within a spend budget per window that the controller sets and the venue enforces before inclusion, so a compromised node key cannot drain it (`spaces-pallet.md` §7) |
| authorities | on Kreivo, a map `(space, account) → anchor key`: each node's own sr25519 account, paired with its ed25519 anchor key, set by the controller; an authority signs `anchor` and `submit`, and the sovereign account pays (`spaces-pallet.md` §7). On JAM, the registered anchor keys alone |
| migration | `Migrate`, by the controller at each venue; each venue refuses anchors outside its range |
| `MaxRootAge` | 24 h: an anchor older is refused and pruned; there is no separate grace |

**The venue's anchor rule:** a registered, unsuspended space; a registered
key; the signature; `Last < w < now_w` (gaps allowed; the open window,
`now_w` itself, cannot be anchored), `now − B_w ≤ MaxRootAge`, w within the
venue's range. A second root for one `(space, kind, w)` is
stored as evidence and suspends the space until the controller removes
both signing keys (`resume`); anyone may submit the second signed anchor.
Until 6.14b no other key can anchor: a space whose equivocating keys are
all its founding keys (always so with a single founder) recovers only by
migrating to a new genesis, another space.

**What an anchor gives:** ordering and non-equivocation, not integrity: a
space can anchor any root of its own making. So every value-moving handler
is two-sided or spends the submitting space's own escrow; slice 6 admits
`Record` alone.

**Time between parties is the venue's** (decision 2's rule). Every time
logic between parties, an expiry, a timeout, an exposure deadline, a
`Seen` entry's age, a format's or program's activation, uses the venue's
chain time (Kreivo's `pallet_timestamp`; a JAM slot × 6 s from JAM's
genesis time), never a window number and never the space's clock. The
space's clock schedules only its own cuts; a venue bounds the windows it
anchors by its own clock (`now_w` is the venue's time read through the
space's frozen clock). A handler that writes a deadline writes a venue
time; a kernel's output names windows only as the windows it read.

**Latency across spaces:**
- **authorization is instant:** a payment between spaces is authorized by
  the paying space's exactly-once message; the counterparty may credit it
  at once, within its exposure cap;
- **trustless settlement** waits for a statement: about
  `L/2 + D + t_prove + inclusion`, the average wait for the cut, the
  close, the proving and a venue's inclusion; about 10 minutes on average
  at L = 10 min (5 + 2 + about 3.5 + under 0.5) [est];
- **the lever below that** is parallel proving (segments across provers,
  the recursion pipelined with the run), not in slice 6.

### Pin E: statements at a cut

Rests on decisions 5, 6 and 8.

- **The keyspace (R4):** committed rows move under a new owner byte,
  `Owner::Committed = 0x03`, key `0x03 ‖ instance ‖ tag ‖ transform ‖ key'`
  (no `Part` byte). VOS keeps one tree per agent over those full keys, the
  leaf the bare value with `salt(seed, full key)`; JAM's whole-keyspace
  tree hashes `0x03` leaves the same way. The VOS agent root is then the
  node of JAM's tree at prefix `0x03`, byte for byte; a map root is the
  node at its prefix. Every key under `0x03` is a committed value row;
  anything else stored there is corrupt, and both hosts fail on it.
- **The method:**
  `#[attestable(gas = N)] fn f(&self, #[public] a: A, …, b: B) -> O`.
  `&mut self` stays refused. `self` is a generated read-only view whose
  `CommittedMap` fields answer from the verified set and trap on any other
  key; plain fields and tables fail to compile. The view is `<Actor>View`,
  its maps `ServedMap`s. The schema tells the agent what a kernel returns
  (6.13): `Kind::Attestable` a method of no public part, its output alone,
  as before; `Kind::Stating` a rootless method with public arguments;
  `Kind::Reading` a `&self` method, run at a cut alone. Its `VOS_ATTEST`
  entry marks it too (bit 32 of the method word), so the derivation gives
  its kernel argument pages for the arguments and the served rows
  (192 KiB), read 64 KiB a witness-input call, as a class's pages allow
  one call; a derivation refuses an entry and a schema that disagree.
- **`#[attestable(venue_bound)]`** adds a leading `venue: VenueId`
  public argument (decision 8).
- **`public_args`** is the concatenation of the encodings of, in order:
  the venue (if venue-bound); `(AgentId, InstanceId)` (if `&self`); each
  `#[public]` argument. So `public_args[..32]` is the venue of a
  venue-bound program. The encodings are the workspace codec's
  (`vos-pvm-codec`): SCALE's for fixed-width types, a `u32` LE length
  before a variable one where SCALE has a compact (6.13).
- **The io-hash is unchanged:** `BLAKE2b-256("vos/io/v1" ‖ SCALE(public_args) ‖ SCALE(output) ‖ SCALE(roots))`.
- **The kernel's halt:** its returned bytes are
  `KernelReturn { public_args, output, roots }`'s encoding (the
  workspace codec's, as `Served`'s below: `u32` lengths), and φ9..12 the
  io-hash over them. The agent splits them, recomputes the io-hash and
  compares it with φ9..12; a mismatch fails the attest (a kernel bug).
  A `Kind::Attestable` kernel returns its output alone, unchecked as
  before; the check costs the caller `IO_HASH_BLOCK` (8,000) a block of
  the return, and an attest is priced apart from a call, `ATTEST` 66,000
  [measured, 6.13].
- **The record:**
  `Attest { program, window: Option<u64>, witness_input: Vec<u8>, output, public_args, roots: Vec<RootRead> }`,
  `witness_input` the arguments ‖ `Served`'s encoding for an at-cut attest;
  the kernel reads it through `0x401`. The final proof's hash arrives
  later as a `Proven { id, proof }` input.
- **The served witness**, SCALE, carried inline in the `Resume` input
  (6.0a: no host call reaches a blob at refine):

  ```rust
  pub struct Served {
      pub space: SpaceId, pub window: u64, pub agent: AgentId, pub instance: InstanceId,
      pub agent_root: [u8; 32],   // A at cut(w)
      pub rep_root: [u8; 32],     // A_rep at cut_rep(w)
      pub rep_salt: [u8; 16],     // the representative leaf's salt, from its seed
      pub space_path: Vec<u8>,    // BatchProof: RepKey(agent, 0, w) → agent_root, against rep_root
      pub rows: Vec<(Vec<u8>, Option<([u8; 16], Vec<u8>)>)>,  // full row keys in order; None: absent
      pub rows_proof: Vec<u8>,    // one BatchProof against agent_root
  }
  ```
- **The prologue** checks each row key starts `0x03 ‖ instance`, verifies
  `rows_proof` against `agent_root` and `space_path` against `rep_root`,
  computes `S_w`, and states
  `RootRead { kind: Space, space, window: w, root: S_w }`. A failure
  traps: the attest fails, and the workflow sees the error.
- **What a statement binds of its reader:** `public_args` carries the
  `(agent, instance)` whose rows it read, not the program installed there:
  a kernel states over any instance's rows of a map of its tag, and a
  map's tag derives from its name. That is within "an anchor gives no
  integrity: the space is trusted for its own state"; a venue's handler
  knows what program each `(agent, instance)` it trusts runs (6.13's
  review). Binding the install's program hash is a later slice's.
- **When:**
  1. `ctx.attest_at_cut(call).reads(|r| …).await` from a workflow step
     (`Op::AttestAt`) records a pending request of window w and pauses
     the workflow, `WorkflowState::Attesting`, until `B_{w+3}`
     (`READ_WINDOWS`), then `AttestError::NotClosed`. Refused at once,
     the workflow going on: an agent of no space (`NoSpace`), a method
     not `Reading` (`Unknown`), arguments past `Limits::attest` (`Cap`),
     rows none, past `MAX_READS` (256), not strictly increasing or not
     each a committed row of the instance (`Reads`); range reads are out
     of scope.
  2. The agent's cut build generates its `rows_proof` (6.12), and its
     leader, woken by the builder's finishing commit (`Woke::Built`),
     proposes a system input `Report { to, w, root, pending }`, whose step
     sends the representative's `report` the
     `AgentRoot { kind, w, root, pending }` (the agent the message's
     sender) on their pair, exactly-once, once a window
     (`keys::reported`), only once the node knows the representative.
     The representative stores `root` under `RepKey(agent, 0, w)` and,
     with `pending`, the agent under `asked`.
  3. **The paths' return:** the representative's own cut build at
     `cut_rep(w)` keeps, beside its root, the salt and `BatchProof` of
     `RepKey(agent, 0, w)` for each agent that asked whose row the cut
     holds (`keys::closing(w)`, node-local, the same bytes on every
     replica). Its leader, woken as an agent's is, signs the anchor of
     `S_w` with its node key and hands it to the venue (a repeat of the
     same root is the venue's `Again`; a refusal for now, the venue's
     clock still in the window, is tried again at the next batch, the
     later windows behind it), then proposes
     `Close { w, rep_root, paths }`, whose step sends each agent past the
     close mark (`keys::close_mark`, at most 8 a close, in agent order)
     one pair message, exactly-once:
     `Closed { w, rep_root, rep_salt, space_path }`. One path an agent
     and window, not one a request: the representative learns of no
     request, and every read of the agent at w reads the same row. The
     agent's apply stores it as a replicated row keyed by window
     (`keys::closed(w)`), only from the representative it reported to,
     and ignores a second `Closed` for a window it holds.
  4. The agent's leader assembles `Served` from the two and proposes a
     system input `Resume { window, request, served: Option<Vec<u8>> }`,
     the bytes `Served`'s encoding, bounded by `Limits::served` and not
     `REQUEST`, `None` when they pass the cap (`AttestError::Unserved`);
     refine checks the served header and row keys against the agent, its
     space, the window and the request, and `rep_root`, `rep_salt` and
     `space_path` against the `closed` row of the served window, else
     `Unserved`, so the live `Attested::Done` a workflow acts on is as
     true as the replicated close, not as the leader serving it; then
     runs the kernel live on the arguments ‖ served and records the
     `Attest`; the workflow resumes with
     `Attested::{Done(output), Failed(AttestError)}`, a kernel's trap
     `Failed`; its record keeps that answer, never the served bytes. The
     kernel's gas and the attest's price come out of the resumed step's
     limit; the agent's work on the rows, `SERVED_BYTE` (64) a byte
     [measured, 6.13], out of the batch's budget, as a precompile's
     serving is.
- **A window not closed in time:** apply, recording the cuts whose first
  window is w′, re-cuts the reads the latest earlier cut w serves when
  `closed(w)` is not there: `moved(w) = w′` (replicated). The cut at w′
  proves them again, its proof kept beside the one at w
  (`cut_proof(request, window)`), and the agent's report of w′ marks it
  pending. Refine accepts any window of the read's chain (its own, then
  each it moved to, at most `RECUTS` moves) whose close the agent holds;
  serving it at the first whose cut its replica built is the leader's
  choice, not a rule: a close that comes after the re-cut still serves it
  at its own window. Its deadline `B_{w₀+3}` (`READ_WINDOWS = 1 +
  RECUTS`) comes when its third re-cut would: the workflow sees
  `AttestError::NotClosed`. A representative returning after several
  boundaries closes them at one version without the agents' late rows;
  their reads take this path. A read asked in a window a clock's jump
  past `MAX_CUTS` left uncut is past its deadline already.
- **The caps:** `Limits::attest` keeps capping the caller's arguments (64
  KiB on VOS, 2 KiB on JAM), and the kernel's whole return
  (`KernelReturn`'s encoding). `Limits::served` caps a `Resume`'s `Served`:
  128 KiB on VOS (about 155 rows [est, 6.0a]), 32 KiB on JAM (6.13)
  inside CE 133's package bound (pin F); JAM's step effects then take
  about 65M of a package's own work, a 24th of VOS's, its worst step
  still a package. An at-cut attest counts 2 against `Limits::attests`,
  so `cap.rs`'s attest term bounds it unchanged: the per-attest framing,
  re-derived for `window`, `public_args` and `roots`, is 64 B, and
  REQUEST + 128 KiB + REPLY + 64 ≤ 2 × (REQUEST + REPLY + 64), asserted.
- **Retention (W1):** none past the cut. A request made in window w reads
  at `cut(w)`: at most one window of latency.

### Pin F: the venues' check order

- **`vos_statement`** gains: an accepted *set* of formats (`admit`'s
  `format != FORMAT` goes); `Venue::id() -> VenueId`; a pin
  `Pin { program: ProgramId, venue_bound: bool }` in place of the bare id;
  `Refusal::Venue` (code 7) for a venue-bound statement whose
  `public_args[..32]` is not the venue.
- **`judge`, in order:** the format accepted; the program equals the pin;
  the venue prefix if venue-bound; the space rule (rootless: `NONE`;
  otherwise the space is not `NONE` and every root's is the statement's); every root anchored
  (within the venue's migration range); the io-hash recomputed and the id;
  unseen; the proof (at most 256 KiB, the format's own decode, nothing
  after it) against the pinned program id and the recomputed io-hash.
- **`Seen` and time:** a rooted statement's entry may be pruned once its
  newest root is past `MaxRootAge`, since a replay then fails `0x5`. **A
  rootless statement's entry never expires:** it has no anchor to fail,
  so a pruned entry would let it be accepted, and handled, again. Their
  count is bounded by what a submit costs (decision 11). The same rule at
  every venue. **`MaxRootAge` is never raised in place;** a raise is a
  migration that first prunes anchors older than the old bound: a `Seen`
  entry's expiry was computed with the old bound, while `anchored`
  recomputes the age with the new one, so an anchor not yet pruned would
  be fresh again after its entry was dropped, and a replay accepted.
- **Kreivo's `submit`** (`spaces-pallet.md` §6.3, the teammate's to
  build): the bounded lengths (statement 64 KiB, proof 256 KiB); the pause
  flag; the paying space active and the signer one of its authorities;
  the sovereign account holding `SubmitDeposit`; then, returning Ok so the
  deposit's fate persists, the decode, the registry's pin and `judge`. On
  acceptance `Seen` is inserted, `Record` runs and the deposit is
  released; a repeat (`6`) releases it, since two nodes can race; any other
  refusal forfeits it to the treasury. A refusal before the proof refunds
  to the early weight.
- **JAM:** the statement in the `Submit` item's payload, the proof its
  extrinsic (JAM-NP CE 133 bounds a package at 204,802 B [6.0b]); refine
  runs every check but `anchored` and `seen` (it reads no state) and the
  proof, and outputs `Verdict { id, program, space, roots, code }`;
  accumulate checks `anchored` and `seen` and records, under the same
  `Seen` rule. A fixture fails exactly one check, so every venue reports
  the same class.

## M2: the final wrap masked

6.0 opens the slice. 6.1–6.6 are M2's line; 6.7–6.9 run beside it, 6.8
from the first day.

### 6.0 The remaining feasibility spikes, and the docs

Throwaway code on local branches; each with a gate and a fallback.

- **6.0a The in-kernel prologue, measured before the keyspace changes**
  (Fable's finding 16).
  - **What:** a hand-assembled `Served` against an existing map root and a
    fabricated representative tree of 1,024 agents, read by a prototype
    prologue in the test harness: the rows' multiproof, the space path,
    `S_w`, `public_args` and the io-hash with the root. Two kernels: one
    row (a balance), and 16 rows (window-like).
  - **Measure:** steps, compressions and witness bytes per row and for
    the path; segments; proving time.
  - **Gate:** the path at most 30 compressions and 1 KiB at 1,024 agents
    (about 13 and 0.45 KB [est]); a row at most 25 compressions and 1 KiB
    (about 20 and 812 B [est]); the 16-row kernel at most 1M steps.
  - **Fallback:** up to 2× over, accept and size `Limits::served` from the
    measurement; beyond, profile `verify_encoded` in the guest (decode or
    hashing) and fix it inside 6.13 before the SDK fixes its shape.
  - **Also decided here, by reading:** that the node's blob store can hand
    a blob to a step's refine at resume (slice 4's 4.4a path). If it
    cannot, the fallback is inline: `Limits::served` 128 KiB and `ATTESTS`
    8 for `attest_at_cut`, keeping `cap.rs`'s asserts.
  - **Output [done]:** transport inline; `Limits::served` 128 KiB on VOS,
    an at-cut attest counting 2; a row 19.07 compressions and 842 B, the
    path 14 (+1 for `S_w`) and 590 B at 1,024 agents, 16 rows 205,841
    steps [measured].
- **6.0b The JAM venue's program and PolkaJam.**
  - **Build** `final-verify.elf` from spike 6a's branch with format 39
    alone, at opt-levels 3, `s` and `z`, stripped, fat LTO and one codegen
    unit: bytes and gas each.
  - **Gate (informative):** the masked-only program under 512 KiB keeps an
    actor-hosted venue possible; the dedicated service's cap is the
    Gray Paper's 4,000,000 bytes, so 6.19 proceeds either way.
  - **Probe** PolkaJam 0.8.0 (GP 0.8.0, gas per basic block) with slice 4's
    `just jam-testnet`, and compare one refine's gas against the JAM-only
    host's.
  - **Fallback:** if 0.8.0 does not run the agent, the testnet run in 6.19
    pins the last version that does, and the step records why.
  - **The proof's transport on JAM, decided by the evidence:** read Gray
    Paper 0.8.0's bound on a work item's payload (the bundle's W_B is
    13,791,360 bytes) and submit one 170 KB item to PolkaJam. **[done]** A
    170 KB item fits, but JAM-NP CE 133 caps a package at 204,802 B,
    under pin F's 256 KiB: 6.19 carries the proof as the item's
    extrinsic, the preimage path for the harness alone.
- **6.0d The docs.** Copy the staged research into `research/slice-6/`;
  open `slice-6-progress.md`; apply `doc-fixes.md`'s items tagged [now]
  and [decision N] (the decisions are taken); the [step 6.x] items land
  with their step; rename the Clerk's draft to `clerk-across-spaces.md`
  (decision 15).
- **6.0e A Rust client on a Kreivo dev chain** (for 6.17b).
  - **What:** start a dev chain from Kreivo master's runtime
    (`polkadot-omni-node` stable2606-2 in `--dev` mode with Kreivo's dev
    preset; chopsticks if dev mode fails), and from a Rust client with an
    sr25519 dev key: submit one signed stock call
    (`System::remark_with_event`), its call bytes built by hand as the
    pinned spaces calls will be, the envelope (signed extensions, nonce,
    era) from the live metadata; follow it to inclusion, read its event
    from `System.Events` by extrinsic index, and read a raw storage key
    back (`System.Account`).
  - **Also learned:** the subxt release that reads stable2606-2's
    metadata, and Kreivo's signed extensions as the envelope needs them
    (`ChargeSpaceFee` keeps the same identifier and data,
    `spaces-pallet.md` §7, so the envelope does not change with it).
  - **Gate:** the round trip works with subxt, its version recorded.
  - **Fallback:** raw JSON-RPC (`author_submitAndWatchExtrinsic`,
    `state_getStorage`) with the calls SCALE-encoded by hand, since their
    shapes are ours; 6.17b's estimate takes its upper bound.
  - **Output [done]:** the round trip with subxt and subxt-signer 0.51.1
    on omni-node stable2606-2 and Kreivo 87f8728 (spec 134); no fallback.
- **Reviews:** Opus on the spikes' logs.
- **Estimate:** 1.5–2 weeks (6.0a 3–5 days, 6.0b 1–2, 6.0d 1, 6.0e 1–2).

### 6.1 Format 39 and the masked security count (F)

- **Files:** `pvm/proof/src/{format,security}.rs`,
  `pvm/proof/src/format_masked_tests.rs` (from `1b76b028`).
- **The tool:** `SecurityShape::composition_point_doublings` (j, the DEEP
  term ×2^j; 0 in every existing shape) and `SecurityShape::variant_c()`
  (log degree bound m+2, trace length m+1, composition bound m+2, j = 1).
  The masked shape is taken from its own layout (k = 4N whole), never
  through `framework_access`' split-subtracting helpers.
- **The entry:** pin A, `Reserved`; 40 into `RETIRED`, with its reason in
  `RETIRED`'s doc;
  `MASKED_WRAP_REFERENCE` from `WRAP_REFERENCE.variant_c()` plus R2's
  blinding.
- **Tests:** every unmasked format's pinned bits unchanged (28 at 146 /
  82.60); 39 at 146 / 82 (82.69–82.70); the least-query grid pinned for
  A and B; the masked wrap needs affine batching (by powers: 76.98, at
  the 538 batched values 6.2 counts).
- **Review (Fable), what it must check** (spike 6b §4):
  - DIVERGENCE-012's citation and the affine premise in pin B's order;
  - DIVERGENCE-011's round list `[3,3,3,2]` at log k = 17 against the
    fork's `FriVerifier::commit`;
  - the DEEP term's three (c) inputs (k = 2N, d = 3, 2^j);
  - the integer-multiplicity quantization;
  - R3 met by an 8-column R (pin C), with R's 8 sampled values in the
    shape (the count is expected unchanged: the query term binds).
- **Fallback, if DIVERGENCE-012 falls:** a batching-phase PoW of at least
  4 bits at blowup 32 (a new number), or blowup 8 with 41 queries (about
  2× verify).
- **Estimate:** 0.5–1 week.

### 6.2 The masked AIR variant (F)

- **Files:** `pvm/proof/recair-air/src/{p2,qm31,h8}.rs` (each `evaluate`
  split into `body()` and `finalize_logup_in_pairs()`); `masked.rs` (new,
  no_std): `MASKED_LOG_CONSTRAINT_EXPANSION = 2`, `BlindRelation`,
  `MaskedEval<B>`, the `MaskedComponents` trait (a component set and its
  log sizes), `MaskedComponent`, `committed_log_sizes`,
  `sample_points -> Option<_>`, `composition_point` (π(z)),
  `composition_oods_eval`.
- **Design:** wrap-only. Leaves and folds never reference it, and
  `LOG_CONSTRAINT_EXPANSION` stays 1 for them; the blinding columns live in
  `MaskedEval`, never in the shared components.
- **Tests:**
  - the masked degree audit: every constraint ≤ 3 (masked `p2` 303
    constraints, `qm31` 4, `h8` 8 [measured]);
  - a static check that only `MaskedEval` uses `BlindRelation`;
  - **R5 for slice 7, cheaply:** the same static degree audit over the 25
    segment chips under (c) [done: 5,177 constraints, none above 3]. What
    slice 7's masked segments need beyond it (6.2's review): an
    active-chip mask parameter on `MaskedComponents`, and a finalize hook
    on `Body` if a chip stops finalizing in pairs; and (6.3's review) a
    size floor or a per-component `h`, since `MaskLayout::new` needs
    `log_size ≥ log_mask_rows + 2` (2^10 rows at h = 256) and segment chips
    run below it; at q = 40 and |O| = 2 the segments reveal 128 rows, within
    h = 256 with the 2× headroom exactly;
  - the stale-fixture test: leaf, fold and wrap fixtures, `H_fold` and the
    program ids byte for byte;
  - **the masked reference shape from the built components:** the masked
    wrap's `SecurityShape`, derived from the built `MaskedComponents`' own
    layout (their columns, blinding columns, constraints, fractions and
    sampled values, R's 8 among them; k = 4N whole, j = 1), never through
    `framework_access`' split-subtracting helpers, equals
    `MASKED_WRAP_REFERENCE` field for field (`B` the values the DEEP
    quotient batches, 538: a column sampled twice batches a third, its
    periodicity value; `c` 3), and counts 82.69–82.70, as
    `the_reference_shapes_are_the_segment_airs` does for segments. A
    mismatch corrects the reference in this step, and 6.1's pin with it;
    6.4's check of the verifier's shape compares the same way.
- **Gate:** format 32 untouched, byte for byte; the reference shape equal
  to the built one.
- **Estimate:** 0.5–1 week.

### 6.3 The masked prover (F)

- **Files:** `pvm/proof/recair/src/masked.rs` (from the spike), `trace.rs`
  (`interaction_with(.., extra)`), `wrap.rs`, `prove.rs`.
- **What:**
  - `prove_masked::<MC: MerkleChannel, C: MaskedComponents>(format, …)`:
    `MaskLayout`, parallel `mask_columns`, `commit_salted` writing the salts
    straight into packed SIMD columns (spike 6a's 0.8 s a tree was the
    collect), pin B's order;
  - **from 6.2's review:** the masking's pins (`MaskPins`' salt and `R`
    columns, and `h`) on `Format` for a masked number (R6), `MASKED_WRAP_PINS`
    read from it and `the_masked_reference_shape_is_the_built_wraps` its
    guard; a provided `MaskedComponents::draw(channel) -> (Relations,
    BlindRelation)` writing pin B's step 5 once; a prover-side extension
    trait for `ComponentProver`;
  - R1 with pin C's bounded retry; R4's hedged RNG; R with 8 columns and
    no R3 check; the test seam;
  - `wrap::prove` for format 39 replacing `stwo::prover::prove` at
    `prove.rs:243`; format 28's path kept for tests;
  - every assert and `expect` of the spike's prover an error
    (`MaskLayout::new`'s h ≤ N/4, the sample points, `mask_columns`);
    salts never given a sample point.
- **Tests:**
  - the mask invariant `f'|_H = f`, `(f' − f)/v_H` of exactly h
    coefficients, 2^6 to 2^17;
  - R1 refuses h = 64;
  - on the generic small circuit, `fri_mask_coefficients_independent`
    replays `prove_values`' draw: at 8 columns the span holds on every
    transcript; at 4 columns it detects a planted singular draw;
  - an invalid witness refused by the prover;
  - **generic:** the masked prover and verifier on `Blake2sMerkleChannel`
    with a `p2`-only component set (no format admitted);
  - two proofs of one witness differ in every root and claimed sum; the
    seeded seam reproduces bytes.
- **Gate:** the real masked wrap (window kernel, `test-proof`): heap ≤ 4.5
  GiB, process ≤ 8 GiB, ≤ 15 s quiet (spike: 3.45 GiB, 11.6 s best);
  R1 ≤ 50 ms.
- **Estimate:** 1–1.5 weeks.

### 6.4 The masked final verifier and the fixed-layout decode (F)

- **Files:** `pvm/proof/final-verifier/src/{lib,masked,constants}.rs`, a
  new `layout.rs`.
- **What:**
  - `verify_masked::<MC>` from the spike, no_std, over pin B;
  - `check_shape` extended to every masked tree's width (57 / 381 / 48 /
    20), the samples against the sample points, the composition tree's
    columns, before any Stwo call; the spike's call to format 28's
    `check_shape` replaced by format 39's own;
  - the proof's `log_sizes` checked equal to the format's pin (`[14, 15,
    11]`) before `MaskedComponents::new`, which cannot, and the trees'
    widths before any Stwo call (the tests' verifier's `fits` check, 6.3,
    is the model); the salts, `R` and `h` taken from the format (6.3),
    never from the proof;
  - **the shape tied to the transcript:** `n_deep_values` of the
    verifier's own sample points asserted equal to 538, the reference's
    `B`;
  - **the trust boundary, named:** the two facts the masked verifier
    leaves to Stwo, each pinned by the format and tested: the tree widths
    that `verify_values` zips against (a proof of another width refused by
    `check_shape` first), and the FRI round list `FriVerifier::commit`
    derives from the largest column (17 → `[3, 3, 3, 2]`, asserted equal
    to the security tool's);
  - **dispatch by the accepted set:** `verify(format, accepted: &[u32],
    bytes, words)` takes the format from the statement (never sniffed
    from the proof's bytes, whose encodings differ), refuses one outside
    the set, and runs that format's decode, which checks the proof's own
    header against it; a build feature `test-formats` links 28;
    production links 39 alone;
  - **the fixed layout** (format 39's bytes): the fields in a fixed order,
    little-endian, with explicit u32 counts, no varints; every count
    checked against the format's pin or bound before any allocation;
    nothing after the last field. Its encoding is canonical;
  - constants: `LOG_SIZES`, `PREPROCESSED_ROOT_39` (equal to 28's, its own
    test), the tree widths, `MAX_PROOF_BYTES` 256 KiB;
  - format 39 `Admitted`.
- **Tests:** spike 6a's 14 tamper cases, each refused by an error; the
  salt-count and R-width mismatches; a `vos-pvm-recair` test that the
  verifier's constants (the format number, the configuration, the log
  sizes, the tree widths, the fixed layout) equal the registry's entry for
  39, as for 28; cross-format proofs both ways (`Format`, 0x4);
  every truncation and trailing byte of the layout; the fuzz targets
  extended to 39's bytes (`final_verifier_bytes`, `_mutate`).
- **Gate:** verify ≤ 125M gas on the JAM-only host (≤ 200M hard), the
  decode ≤ 4M (postcard: 19.9M); ≤ 50M Wasm instructions under the PVF's
  semantics; builds no_std for thumbv7em, wasm32 on stable, riscv64em.
- **Estimate:** 1–1.5 weeks.

### 6.5 `vos-statement` at the accepted set, the fixtures, the harnesses (F)

- **Files:** `pvm/proof/statement/src/{lib,model}.rs`, `src/bin/final-verify.rs`,
  `pvm/proof/tests/kernel/fixtures.rs`, `pvm/proof/fixtures/*`,
  `final-verifier/wasm/*`, `justfile` (`judge-wasm`).
- **What:**
  - pin F's `vos_statement` changes; the model's `Policy` gains the venue
    id, the per-program flag, a migration range
    `range: (from_w, Option<until_w>)` per space, and pin F's `Seen` rule;
  - the fixtures regenerated at 39 through the seeded seam (stale test byte
    for byte under the seed), 28's kept under the test policy;
  - **the transition** both ways under the test policy {28, 39}: S
    accepted under 39 then 28 refused as `0x6`, and the reverse;
  - **the adversarial cases**, one a field of the id and the io-hash
    preimages, each a replay of the valid statement with that field
    changed: the space (`0x4`), the format (`0x2`), the venue of a
    venue-bound statement (`0x7`), a root's window (`0x5`), a root
    (`0x5`), the nonce in `public_args` (the proof's words: `0x108` or
    `0x109`), the program (`0x3`), a window outside the migration range
    (`0x5`); and a rootless statement replayed past `MaxRootAge` (`0x6`:
    its `Seen` entry kept);
  - the Wasm blob and `final-verify.elf` link the production verifier
    (39); the test build links both.
- **Gate:** every fixture judged alike natively, in Wasm (PVF and client)
  and on the JAM-only host; the JAM program's size recorded against 512
  KiB and 4,000,000 bytes.
- **Format 28 kept out of production by the accepted set** (6.3's
  review): the prover side stays open, `wrap::prove_unmasked` and
  `prove_on(&WRAP, …)` reachable for the tests and the fixtures; the
  venues' accepted set {39} (28 only under `test-formats` and the model
  venue's test policy) is the one gate, and this step's transition and
  adversarial cases hold it.
- **The build check** (6.4's review), once `vos-statement` drops the
  verifier's `test-formats`: `just check-no-test-formats` beside
  `check-no-seeded-masks`, `cargo tree --workspace -e features,no-dev`
  and the stand-alone manifests (the Wasm blob among them) showing no
  `feature "test-formats"`; `vos-statement`'s `fixtures` and test features
  do not imply it.
- **Review:** Fable as well: the check order, the accepted set and the
  adversarial cases are protocol every venue inherits (a proof checked
  before `seen` is a denial-of-service vector).
- **Estimate:** 1 week.

### 6.6 The masking's gates, and the masked transcript's review (F)

- **Soundness 1–10** (`research/slice-5/spike2-masking.md` §5, amended by
  `masking-review.md`): the degree audit (6.2); masked acceptance at every
  size; a constraint tamper on the first, last and wrap rows, refused by
  the prover and, forced, by the verifier; the mask invariant (6.3); R1;
  lifting across sizes; each masked field tampered (6.4); the blinding's
  soundness (an unbalanced relation cancelled by `Σ B_c` refused); the
  structure errors, never panics; both bit counts pinned.
- **Leakage 1–7:**
  1. rank tests: R1 on every column class, on both channels, at every
     class size; pin C's R3 test;
  2. **witness indistinguishability:** the honest prover's distribution
     does not depend on the witness. N proofs of witness A against N of
     witness B with the same public inputs (the pairs: a zero witness and
     a random one; two amounts differing by 1): per masked field a
     two-sample χ² on 16 buckets of the value's top bits, and one pooled
     two-sample KS over every masked value. **Control:** the unmasked
     prover fails the same test (the zero witness opens to zeros);
  3. **uniformity:** each masked field of the zero witness's N proofs
     against uniform M31, one-sample χ²;
  4. hidden states: a byte search of the proof for a plain hash of the
     private arguments, the step count, a memory root,
     `memory_commitment`, a register other than φ9..12;
  5. fresh randomness: two proofs of one witness differ everywhere; a
     replayed RNG state with two witnesses differs in every opening. That
     the production build has no seam is pin C's build check, not a test;
  6. the claimed-sum control: unblinded a right guess reproduces a sum,
     blinded it does not;
  7. the shape public: the proof's layout depends on the format and the
     Fiat–Shamir coins alone, never the witness.
- **Where:** 2, 3 and 5 on the generic small masked circuit at N = 2,000
  proofs a witness in `slice-gate` (N = 500 in `test-proof`, 64 in `just
  check`), and at N = 32 on the real wrap in `slice-gate` (16 in
  `test-proof`); α = 10^-3 overall, Bonferroni over the
  F fields counted (per field 10^-3 / F; about 10^-8 at the wrap's tens of
  thousands).
- **Their power, stated in the step's log:** at N = 2,000 and a per-field
  α of 10^-8, the per-field χ² finds a leak of about 0.15 in total
  variation [est]; the pooled KS over every value finds a common shift of
  about 10^-3 in the CDF [est]. They are a regression guard against gross
  leaks (an unmasked column, a reused mask, an unblinded sum), not
  evidence of zero knowledge: that is the argument's, R1 on every proof
  in the programmable random-oracle model, which Fable's review checks.
- **The verify gates on a bound** (6.4's review): 6.4's decode (≤ 4M gas)
  and PVF (≤ 50M Wasm instructions) gates were one proof's, within a few
  percent of their limits, and the Merkle witnesses vary by about 10%
  with the query draw; this step measures them on a worst-shape proof (24
  distinct queries, no shared siblings) or as the maximum over at least
  10 seeds. **Unaligned loads** are legal on JAM's PVM (its loads index
  memory by byte, with no alignment condition), so
  `+unaligned-scalar-mem` in `riscv64em-vos.json` is a codegen lever for
  the guest's decode and verify gas (one load where LLVM now emits four
  byte loads and shifts), measured here or at 6.19; it does nothing for
  the Wasm gate.
- **Review:** Fable on the masked transcript as built (pin B), with R1–R4
  and the leakage results. The zero-knowledge argument stays conditional
  on the programmable random-oracle model and R1 on every proof; the
  external audit's scope gains it.
- **Estimate:** 1–1.5 weeks.

### 6.7 Panic-freedom by construction, and fuzzing in CI

- **Clippy, on the verify path:** `unwrap_used`, `expect_used`,
  `indexing_slicing`, `panic` and `arithmetic_side_effects` denied in
  `vos-pvm-final-verifier`, `vos-statement` and `vos-anchor`, each
  allowance justified in place.
- **The fork's verify path at the pin, audited:** every index, `unwrap`,
  `zip_eq` and `assert` reachable from `verify_masked` and format 28's
  `verify` (`vcs_lifted`, `pcs`, `fri`, `verify_values`) listed in
  `pvm/proof/SECURITY.md` with the shape check that guards it. One that no
  check can guard becomes a fork fix (Fable review, then push).
- **The fork fix for the last proof-reachable Stwo panics** (6.4's
  review): `fri_answers` → `denominator_inverses` → `CM31::batch_inverse`
  asserts on a zero DEEP denominator (a sample point's conjugate line
  through a queried point: about 2^70 hashes of grinding [est]), and
  `complex_conjugate_line_coeffs`' `assert_ne!(y, ȳ)` (2^-62 a draw):
  each a `VerificationError::InvalidStructure`, with a unit test from a
  constructed point pair; a DIVERGENCE line in `SECURITY.md`; the fork
  re-pinned (`Cargo.lock`, `fuzz/Cargo.toml`) and pushed after Fable's
  review. Format 28's path and upstream alike.
- **Fuzzing:** the five targets plus a masked-bytes target and an
  `Anchor` decode target; a checked-in corpus replayed in `just check`;
  `just fuzz` (5 minutes a target) in `ci-full`.
- **Gate:** no crash; the audit table complete; every path the corpus
  covers listed.
- **Dep:** 6.4. **Estimate:** 1–1.5 weeks.

### 6.8 The recursion AIR's forgery gates (F)

Beside M2 from its first day: a forgery accepted here changes format 32,
every program id and `H_fold`, and so must be found before any venue pins
them.
- **Each gate a malicious prover** that skips the prover's checks, under
  the hardening's standard (`tests/gates/`):
  - `p2`'s modes and chaining: a sponge chained across rows, a Merkle mode
    swapped;
  - the `Gate` relation's signed multiplicities (R12): a yield consumed
    twice, a negative multiplicity;
  - `assert_one_of`: a choice outside the set;
  - the lane gadgets: an unread lane set nonzero, which no consumer may
    assume zero;
  - the leaf's unchecked boundary bytes: a byte ≥ 256 where A.3's local
    argument does not range-check it.
- **Gate:** every forgery refused by the verifier, with its refusal named.
  An accepted forgery stops M2: the fix takes a successor to format 32 and
  a re-pin of every id, before 6.17 and 6.18.
- **Estimate:** 1.5–2.5 weeks.

### 6.9 Format 36

- **Decision 3 (taken):** retire 36 and delete the refine-bundle proving
  path: the default `prove` and `pvm/bench` move to 35; `refine`,
  `refine_codec`, the refine prover's collector,
  `verify_refine_bundle_authenticated` and their tests are deleted; 36
  joins `RETIRED`, its doc saying the legacy segment format was below the
  60-bit floor.
- **Gate:** no producer or verifier of 36 left; `pvm/bench` on 35; the
  quality review's items that lived in the deleted files (11, 25's
  `refine_codec`, 35's `verify_refine_bundle_authenticated`) recorded as
  gone in 6.22's list.
- **Estimate:** 0.5–1 week.

### M2 acceptance

- **Gates:** `ci-full` (with `just fuzz`), `test-proof`, the checker loop.
- **Recorded:** the masked wrap's time, heap, bytes, gas (decode and
  verify), Wasm instructions, R1 time, per statement, against 28's.
- **Reviews:** an Opus milestone review, then a push.

## M3a: roots, anchors and `&self` reads, on the model venue

6.10 opens it. 6.11–6.15 follow in order; M3b's 6.16 starts once 6.10
lands.

### 6.10 `vos-anchor` and the space's genesis (F)

- **Files:** `pvm/proof/anchor` (new, `vos-anchor`, no_std, `blake2`
  only: its SCALE encodings by hand, canonical, as `vos-statement`'s
  `codec.rs`, so Kreivo's vendored tree gains no crate); `vos-statement`
  re-exports it and its `RootRead.kind` becomes `RootKind`;
  `pvm/proof/precompiles/src/io.rs` (the kernel side's `RootRead.kind`,
  a `u8` that the io-hash covers, becomes `RootKind` with a `u8` wire
  form, refused when unknown, so the SDK's prologue states
  `RootKind::Space`); `agent/wire/src/peer.rs` (`CreationRecord.space: SpaceId`);
  `agent/wire/src/keys.rs` (`keys::space`, `keys::clock`, stored at first
  install like `keys::target`, a later install naming another refused);
  `node/host/src/space.rs` (a `space.genesis` beside the space file);
  `vosx space up` writes it once.
- **Design:** pin D, its types and preimages; ed25519 is the venue's
  (sp_io on Kreivo, `ed25519-dalek` in the node and the JAM service), the
  crate gives digests.
- **Tests:** golden vectors for `SpaceId`, `S_w`, the anchor, registration
  (with its `start_window`) and `VenueId` digests, equal natively, in Wasm and in the PVM; the window
  arithmetic at its edges (exactly `B_w`, before the origin); an unknown
  root kind refused at decode; the fixtures regenerated (their roots were
  kind 1).
- **Dep:** decisions 1, 2. **Estimate:** 0.5–1 week.

### 6.11 The agent root: committed rows under `0x03` (F)

- **Files:** `agent/wire/src/keys.rs` (`Owner::Committed`, the row key,
  `owned_by` and `instance_prefix` accepting `0x03 ‖ instance`,
  `is_committed` and `committed_entry` from the first byte);
  `agent/wire/src/apply.rs`; `node/host/src/roots/mod.rs` (one tree per
  agent; one `RootRow` and one `Built` watermark per agent; `agent_root`;
  a map root as the node at its prefix); `agent/default/src/refine/jam.rs`
  (`0x03` leaves hash the bare value with VOS's salt, the witness still
  carrying stored bytes); `dirty`'s `map_key`;
  `agent/testkit/src/memory.rs`; `base.rs`; the window kernel's
  multiproofs; the fixtures.
- **Design:** pin E's keyspace. In a crit-bit tree with absolute branch
  levels, the keys sharing a prefix are one node's leaves, so the node at
  `0x03` is the VOS agent root (Fable's review checked it against
  `agent/tree`).
- **Tests:** VOS ≡ JAM: the agent root equals the JAM tree's node at
  `0x03`, and each map root the node at its prefix, over random row sets,
  one row and none; the existing comparison suite; ownership refusals on
  `0x03` keys; the builder's crash-resume to the same root; a 64-byte
  `Ordered` key's leaf counted as two compressions.
- **Gates:** the checker loop; the builder keeps up at 20k committed
  writes a second offered (19.6k delivered), no regression past 10%; the
  window kernel's steps and compressions within 5% of before.
- **Dep:** decision 5. **Estimate:** 1.5–2.5 weeks.

### 6.12 Window cuts and the held build (F)

- **Files:** `agent/default` (apply, accumulate), `node/host/src/roots`,
  `node/host/src/leader` (the marker), `agent/wire/src/keys.rs`
  (`keys::cut(w)`).
- **Design (X1, W1, Fable's findings 5 and 6):**
  - **the `Cut` marker:** an empty work result timed at the leader's own
    clock, appended once that clock passes `B_w` and the log holds no entry
    at or past it; it never synthesizes a time, so a trailing leader cuts
    late, never wrongly;
  - **apply** of the first entry with time ≥ `B_w` records `cut(w)` for
    every boundary it crosses (one version for several after a clock jump,
    at most the newest `MAX_CUTS`); the shared apply, on both hosts,
    reading the agent's record (target, space, clock) from the state
    before the result's steps; a record stored in part applies nothing;
  - **the builder** targets `min(latest, the earliest unbuilt cut)`;
  - **`undo(w, key)`** rows are node-local, written by the node's apply
    wrapper, never by the agent's `apply`: for a committed write while
    `cut(w)` is unbuilt and the key's current version ≤ `cut(w)`; the cut's
    build reads them and skips dirty rows past `cut(w)`;
  - **the proofs:** after the cut's build, every replica persists, for
    each pending request of w, its `CutProof` (the rows with their salts
    and values at the cut, the root, the version, and the `rows_proof`;
    deterministic bytes) as a local row under `Owner::Tree`, keyed by
    request, in the commit that marks the cut built: later writes
    overwrite the values, and builds delete the seeds, before `Served` is
    assembled;
  - the agent root at `cut(w)` kept for the two latest built cuts;
  - **an agent of no space** (`keys::space` = `NONE`, 6.10) runs no cuts;
  - **witness builders** serve `keys::target`, `keys::space` and
    `keys::clock` together whenever they serve one: the default agent
    traps on a partial set (6.10's review).
- **The brief starts from the first test.** The crash between the cut and
  its proofs, run under the checker, is written before the implementation,
  as the step's brief, and the implementer builds to it.
- **Tests (the review's acceptance tests):** a crash between the cut and
  its proofs; a leader change between the cut and the close; two pending
  cuts (a builder lagging across two boundaries), both roots equal to a
  rebuild from a snapshot; a fast-clock jump of Δ cutting every window up
  to `w(now + Δ)` at one version; an idle agent's marker; replica states
  equal with node-local `undo` rows (checker).
- **Gates:** the checker loop with workflows and cuts; a committed write
  with a pending cut ≤ 2× the 4.3 µs apply cost; a cut's build plus 100
  pending requests of 16 rows on a 1M-row agent ≤ 1 s.
- **Dep:** 6.11; decisions 2, 6. **Estimate:** 1.5–2.5 weeks.

### 6.13 `&self` attestables and the public-input model (F)

- **Files:** `agent/sdk-macros/src/messages.rs`; `agent/sdk/src/runtime.rs`
  (`attested(public_args, output, roots, io_hash)`, the prologue
  `verify_served`); the SDK's workflow context (`attest_at_cut`);
  `agent/wire/src/{result,abi/cap}.rs` (`Attest`, `Limits::served`, the
  `Resume` input); `agent/default/src/refine/invocation.rs` (run the
  kernel on the arguments ‖ served, split `KernelReturn`, check the
  io-hash, record the `Attest`); `node/jam/src/gas.rs` (JAM's served in
  `effects`, `RECORD` unchanged).
- **Design:** pin E. Until 6.14, a test-only stub stands for the
  representative: a one-entry representative tree the node builds itself.
  Witness decoding hits a class's page budget before its step budget
  (6.0a: 11 segments for 206k steps): a larger-page class for `&self`
  kernels or decode in place, measured with 6.18. An agent of no space
  refuses `attest_at_cut` at request time (`AttestError::NoSpace`), so a
  spaceless node's statements are rootless by construction (6.10's
  review). A program id's leaf-circuit hashes are computed in the prover
  role, over a wiring the relation alone does not check (6.8's second
  yield): an id is trusted only as recomputed from the blob, never as
  submitted (6.8's review). The ask validates its `PendingRead.rows`
  (strictly increasing, so sorted and distinct; each `keys::is_committed` and under
  `0x03 ‖ instance`; bounded in count) and refuses it otherwise: a cut's
  build leaves a request it cannot read unproved (6.12), but none should
  reach it. 6.13's real ask replaces 6.12's test hook
  (`Hooks::request_at_cut`), which it deletes.
- **Tests:** existing rootless attestables unchanged; a `&self` read
  accepted; a key outside the read set traps; a tampered row, a wrong
  agent root, a wrong window, a missing representative row, a row of
  another instance and a wrong `rep_salt` each trap; an absent row
  (`None`) proved; the order of `public_args`; the venue prefix; live ≡
  traced with a served input; the JAM path under its 2 KiB argument cap;
  `cap.rs`'s asserts.
- **Gate:** within 10% of 6.0a's measured costs: a row 19.07
  compressions and 842 B; the path 14 compressions (+1 for `S_w`) and
  590 B at 1,024 agents; the 16-row prologue 205,841 steps (measured:
  20.07 with the view's key hash, 862 B, 14 (+1), 590 B, 210,019 steps,
  +2.0%). The kernel's sixteen keyed reads through its view, about 2,400
  steps each (6.0a read by position), are 6.18's to cost. An at-cut
  attest's weight-2 rule holds with `cap.rs`'s asserts.
- **Dep:** 6.0a, 6.10, 6.11, 6.12; decision 8. **Estimate:** 2–3 weeks.

### 6.14 The representative and the anchors (F)

- **Files:** `agent/representative` (new, `vos-representative`, a system
  actor); the node's cut hook (an agent's leader sends
  `AgentRoot { agent, kind, w, root, pending }` on its pair after the cut's
  build; the representative's leader sends `Closed`, pin E); the agent's
  apply of `Closed` (`keys::closed(w)`) and the request's re-cut;
  `node/venue` (new, `vos-venue`: `trait VenueClient { id, anchor,
  submit, anchored }`, `ModelVenue` over `vos_statement::model`).
- **Design:** pin D's representative: its committed map keyed
  `(agent, kind, w)`, its clock offset by D, so its own cut is the close;
  `S_w` from its agent root; the anchor signed by its leader's node key
  and handed to the venue client; `space_path` generated by the same held
  build, only for agents that asked (`pending`), and returned in one
  `Closed { w, rep_root, rep_salt, space_path }` pair message an agent,
  after the anchor is signed; missed windows closed on return within
  `MaxRootAge`; pin E's re-cut of a request whose `Closed` has not
  arrived by the next cut recorded after w.
  - **The leader learns a cut's build has finished:** the builder's
    finishing commit wakes the leader (a `Woke::Built` from the builder's
    loop to the leader's `take`), which then sends `AgentRoot`; nothing
    wakes it there in 6.12.
  - **Pruning `cut(w)` rows** [decided]: apply, recording the cuts whose
    first window is w, deletes the `cut`, `moved` and `closed` rows of
    every window before `w − CUT_KEEP`, `CUT_KEEP = 2 + RECUTS = 4`, a
    consensus constant. A read lives from its window w₀ to its deadline
    `B_{w₀+3}`, its serving window at most w₀ + 2, so no row before
    `w − 4` serves a live read, and one window more covers a close's lag.
    No scan: the windows deleted run from `CUT_KEEP` before the latest
    earlier recording's first window through the batch-time mark's, past
    which no earlier recording cut, at most `CUT_KEEP + MAX_CUTS + 1`
    rows, each read before it is deleted (JAM's witness serves it).
    `pending()` reads past the latest built cut and is unaffected; a
    replica down longer than four windows skips those cuts, whose reads
    re-cut or end `NotClosed` as on every replica; their undo rows go as
    orphans once a later cut is built. A `Closed` of a window already
    pruned is not taken.
  - **The served path bound in refine** (6.13's review): `serves`
    requires `served.window` to be in the request's chain and
    `served.rep_root`, `rep_salt` and `space_path` to equal that window's
    `closed` row; `a_report_is_stored_as_a_read_proves_it` pins that the
    representative's `roots` map stores exactly `representative_row`'s key
    bytes and a bare 32-byte value, its `asked` table the key the node
    reads, and its `report` the method id the agents call.
  - **Catch-up by log across many windows** [decided: no node-local
    cap]: the pruning bounds it already. A replica replaying its log
    applies each recording's deletes as it goes, so the cuts pending
    behind its builder are never more than `CUT_KEEP` windows' and one
    recording's (`MAX_CUTS` at one version after a jump): each committed
    write of the replay writes at most that many undo rows, and each cut a
    build pass. A cap would bound it no further in the common case and
    would make replicas hold different proofs, so a leader change would
    find some reads unprovable; the jump's worst case, 32 cuts at one
    version, each with its own undo rows, is left to 6.19's ops note.
- **Tests:** three nodes, three agents and the representative: every
  agent reports; an agent whose clock leads by more than L − D (its w+1
  row leaves `S_w` alone); an agent that misses the close (its statement
  at w refused by the prologue, at w+1 accepted); a representative
  failover between the reports and the close (the same `S_w`, no
  equivocation); **a representative leader change between `cut_rep(w)`'s
  build and the `Closed` send** (the new leader re-sends; the agent's
  apply ignores the duplicate; the request resumes once); an equivocation
  caught at the model venue.
- **Expected outcomes for a missed close, stated:** an agent that misses
  the close, and every pending request when the representative is down
  across three windows, is re-cut at the next window and resumes there;
  after 2 re-cuts the workflow sees `AttestError::NotClosed`. An agent
  whose clock leads by more than L − D re-cuts each read before its close
  comes, and is served at the read's own window when the close does.
- **Gates:** the checker loop with the representative; `S_w` equal on
  every replica.
- **Dep:** 6.12, 6.13; decision 7. **Estimate:** 1.5–2 weeks.

### 6.15 Statements at a cut, end to end, on the model venue (F)

- **A test actor, `balance`** (`agent/test-actors/balance`): a
  `CommittedMap<Account, Balance>` and
  `#[attestable] fn at_least(&self, #[public] commitment: Commitment, #[public] threshold: u64, salt: [u8; 16], account: Account) -> bool`,
  the account public only as a salted commitment.
- **The fixtures' next regeneration** adds a code-4 case: a rooted
  statement claiming `SpaceId::NONE`, its roots of `NONE` and anchored
  (pin F's space rule, 6.10's review).
- **The window kernel restated** under decision 6 (S3): cumulative pair
  rows, `c_prev` as a `#[public]` argument, the old cumulative values
  private, the current rows read at one cut; output `(net, seq, c_new)`;
  rooted, with no anchors in its output. If cipher-clerk's
  `settlement::window` cannot take one anchor without a library change,
  the test actor nets the delta itself and the library change goes to
  the Clerk's slice.
- **Proved** under 28 in the harness (39 once M2 lands), judged at the
  model venue: accepted; then an unanchored root, another window, another
  space, a missing representative row, a tampered row, a key outside the
  read set, a venue mismatch, a window outside the migration range.
- **Measured:** witness bytes and compressions per row and for the path;
  steps; segments; proving time; latency from `B_w` to the recorded
  `Attest` and to the anchor.
- **Gates:** the measurements within 20% of 6.0a's; the restated window
  kernel ≤ 1M steps; latency ≤ L + D + 10 s at L = 2 min.
- **Review:** Fable as well: the window kernel's restated public inputs
  (`c_prev` public, the cumulative rows) are the protocol the Clerk
  inherits.
- **Dep:** 6.13, 6.14; decision 6. **Estimate:** 1–2 weeks.

### 6.14b A rotatable anchor key (F)

6.14 signs anchors with the representative's leader's node key (its
PeerId key, which cannot rotate) and keeps the representative's replicas
to founding nodes, so a venue's anchor-key rotation (`spaces-pallet.md`
`add_authority`, `remove_anchor_key`, `resume`) reaches no node, and a
single-founder space that equivocates is dead at its venue.
- **Files:** the node's key store (`node/host`: an anchor key beside the
  node key); `node/host/src/leader/close.rs` (the signer);
  `agent/representative` and the node's replica rule; `vos-venue`
  (`VenueClient::anchor_keys(space)`, `ModelVenue`'s keys by space, added
  and removed); `node/cli` (`vos node anchor-key rotate`).
- **Design:**
  - a separate ed25519 anchor key per node in its key store; a founding
    node's first anchor key is the key its genesis names, so existing
    spaces anchor as before;
  - the leader signs with the key the venue lists for it: it reads the
    space's registered anchor keys (Kreivo's `AnchorKeys`, the model's
    set) and signs with its own key among them, refusing to sign
    otherwise (an alert, never a guess);
  - any node holding a registered anchor key may replicate the
    representative, not founding nodes alone;
  - `vos node anchor-key rotate` makes a new key and prints it, for the
    controller's `add_authority(space, who, Some(key))`; the node signs
    with the new key once the venue lists it, and the controller then
    removes the old one.
- **Tests:** a rotation end to end on the model venue (anchors before,
  during and after, no window missed); an equivocation in a
  single-founder space resumed after the rotation; a leader whose key the
  venue does not list refuses to sign; a non-founding node with a
  registered key replicating the representative and anchoring after a
  failover; the key store's crash between the rotation and the venue's
  listing.
- **Dep:** 6.14; `spaces-pallet.md` §6. **Estimate:** 1–1.5 weeks.

### M3a acceptance

- **Gates:** `ci-full` (its `test-proof` among them), the checker loop
  with cuts and the representative.
- **Recorded:** 6.15's measurements; the builder's rate; the cut's cost.
- **Reviews:** an Opus milestone review, then a push.

## M3b: Kreivo, the design and the kit

Slice 6 writes no pallet. The Kreivo teammate builds `pallet-spaces` from
the design; slice 6 delivers what the teammate and the node need, and
gates on a mock of the designed interface. Its weights, benchmarks and
fees are the teammate's.

### 6.16 The verifier kit and the spaces pallet's design

- **The design committed:** `docs/design/spaces-pallet.md` (the staged
  handoff design), with its research in `research/slice-6/`; its §13
  questions stay in it as recommended defaults for the teammate and the
  owner to confirm. They do not block slice 6: the mock (6.17) and the
  client (6.17b) follow the recommended defaults, and a different answer
  regenerates the vectors.
- **The kit, in vos-core:** `just vendor-verifier <dir>` writes
  `vos-anchor`, `vos-statement`, `vos-pvm-final-verifier`,
  `vos-pvm-recair-air` and `vos-pvm-poseidon2` with concrete manifests (no
  workspace inheritance), Stwo as a git dependency at the pin,
  `default-features = false`, and a `VENDOR` file naming the VOS tag and
  the tree's hash.
- **The sync check:** `just vos-sync <dir>` recomputes the vendored
  tree's hash against the tag `VENDOR` names, and regenerates the
  conformance vectors and the golden fixtures from that tag, refusing any
  difference. It runs in a Kreivo checkout as in vos-core. Built as
  `pvm/proof/kit/vos_kit.py` (Python 3.11 and git, nothing of Rust),
  which the kit carries: the sync vendors the kit anew from the commit
  `VENDOR` names, by that commit's own script, the fixtures and vectors as
  committed there, and compares every file (`spaces-pallet.md` §3.1).
- **Tests:** a `just check` test builds the vendored tree alone for
  `wasm32v1-none` on stable (Kreivo's toolchain, 1.94.1) and refuses a
  `std` feature reaching it; the sync check refuses a one-byte change in a
  vendored file.
- **`spaces-pallet.md` §3** takes 6.10's decisions: `SpaceGenesis`'s
  nodes as a compact count, then each its number (1 byte) and ed25519 key
  (32), numbers strictly ascending, 1 to 16 founding keys
  (`MAX_FOUNDING_KEYS`).
- **Dep:** 6.10. **Estimate:** 1–1.5 weeks.

### 6.17 The reference mock and the conformance vectors (F)

- **Files:** `node/venue/kreivo/mock` (in `vos-venue`, test-only, std): a
  plain Rust model of `spaces-pallet.md` §4–§8, not a FRAME pallet: its
  storage under the pinned raw keys (`twox128("Spaces") ++ twox128(item)
  ++` the pinned hashers), its calls by their pinned bytes
  (`[90, call_index] ++ SCALE(args)`), its events and errors by their
  pinned indices, the deposits, the spend budget and the sovereign
  account's payment of an authority's fees (the `ChargeSpaceFee` outcome:
  who paid), time from a settable `now_ms`; the verdicts from the real
  `vos_statement::judge`. Its events and stored values go through
  `parity-scale-codec` derives on types whose variants and field order are
  the design's tables, so its bytes are FRAME's, not hand-rolled
  (`parity-scale-codec` as a std, test-only dependency, outside the
  vendored tree).
- **The vectors:** `conformance/spaces.json`, G1–G18 (`spaces-pallet.md`
  §10), committed in VOS and named in `vos_kit.py`'s `CONFORMANCE`, so the
  kit carries them and the sync check holds them to the tag's; generated
  by running each scenario through the mock over our fixtures: the format-39 fixture (G6), one mutant per refusal class
  (G7), the repeat (G8), the rootless and rooted replays past
  `MaxRootAge` (G9), the budget (G13), and every call G1–G12 left
  uncovered (G14–G18: `migrate`, the controller and keys, `set_status`,
  `dispatch_as_sovereign`, `set_format`'s delay, `on_idle`, the
  registration refusals, a payer other than the statement's space); each
  with its pre-state, `(signer, call hex)`, the expected result, events,
  raw storage writes, and the balance deltas split as the design's §10
  says: deposits exactly at pallet level, fees by sign only in the `fees`
  vectors, since the amounts are the teammate's weights. Also
  the mutation lists of spike 6c's in-Wasm sweep (proof and statement
  mutants, and format 39's masked fields) as data, so the teammate's
  benchmark helper runs them.
- **G4 covers the open window:** an anchor at `now_w` refused
  (`WindowInFuture`), then accepted once `now_ms` passes `B_w`.
- **Tests:** the mock passes G1–G18; each vector's expectation checked by
  hand against the design's text in the review; the vectors regenerate
  byte for byte.
- **Review:** Fable as well: the vectors are the contract a pallet we do
  not write must meet.
- **Dep:** 6.5 (the masked fixtures), 6.10, 6.16. **Estimate:** 1.5–2.5
  weeks.

### 6.17b The node's Kreivo client (F)

- **The anchor is handed over inside the representative's leader's
  batch** (6.14): `VenueClient::anchor` must not block there. The Kreivo
  client queues the extrinsic and answers at once (taken, refused for
  good, or `Open`: tried again at the next batch, in window order).
- **Files:** `node/venue/kreivo` (in `vos-venue`, behind a `kreivo`
  feature); the operator and controller tooling over the same `calls`
  layer: `vosx space venue register` (call 0, the founder's signature over
  the registration digest with its `start_window`),
  `vosx space venue authority add|remove` (calls 2–3) and
  `vosx space venue budget` (call 10), which 6.21's mock leg uses to set
  its space up; `KreivoVenue: VenueClient`, in two layers: `calls` (the
  pinned call bytes, storage keys and event decoding of
  `spaces-pallet.md` §9) and a `Transport` trait (submit signed call
  bytes, follow to inclusion, read events and raw storage), with a subxt
  transport (subxt and subxt-signer =0.51.1, sr25519; `RawCall` payloads;
  tested on omni-node stable2606-2 and Kreivo 87f8728, spec 134) and a
  mock transport over 6.17's model.
- **Design:**
  - **the key (decision 12):** one sr25519 Kreivo account key per node,
    generated and held in the node's key store beside its ed25519 node
    key, never the same key, never logged; the controller registers it as
    an authority paired with the node's anchor key; the node holds no
    balance: the space's sovereign account pays;
  - `anchor` and `submit` built from the pinned bytes, the envelope from
    Kreivo's live metadata; `PassAuthenticate` pinned to None by a typed
    extension, never by frame-decode's fallback, and the live extension
    list checked against the expected ten in order, an unknown one
    refused before signing; the verdict from `Accepted` or
    `Refused { code }` mapped to `Refusal`'s codes, `Refused { 6 }` as
    accepted, the errors mapped per the design's §9: before sending an
    anchor, the client reads `Timestamp.Now` and waits until the venue's
    clock has closed the window (`w < now_w` by the venue's time); 14
    `AlreadyAnchored` and 15 `WindowNotAfterLast` done; 16
    `WindowInFuture` waits until `Timestamp.Now` passes `B_w` plus one
    block and resubmits, never skips (a skipped anchor leaves the window
    unanchored for good); 17 `WindowTooOld` and 18 `OutOfRange` dead, with
    an alert; 7, 19–21 and `InvalidTransaction::Payment` (the budget or
    the sovereign's funds) a configuration or funding alert;
  - `anchored(&RootRead)` reads `Anchors` at the best block; a funding
    alert when the sovereign account's balance falls below N submits'
    deposits and fees;
  - an extrinsic never re-signed with a new nonce while the first may
    still land; retries with backoff;
  - the representative's anchor hook and the worker use it through
    `VenueClient`, chosen by the space's venue in the node's
    configuration;
  - **the `kreivo` venue is not selectable in a production node's
    configuration** (a refused configuration value outside test and dev
    builds) until M3b's deferred Kreivo gates (1) and (2) pass, so no space
    anchors on a chain whose pallet has not met the vectors.
- **Tests:** through the mock transport, G1–G18 driven by the client's
  own encode and decode; an anchor sent at `now_w` waits and lands once
  the mock's `now_ms` passes `B_w`; the budget's refusal raises the alert;
  a lost connection mid-submit (no double submission); key-store tests;
  the production configuration refusing `kreivo`. Through the subxt transport on 6.0e's dev
  chain: the envelope, the nonce, inclusion and event reading with a stock
  call.
- **Gates:** every vector passes through the client; every error and
  refusal code mapped; no double submission under a reconnect.
- **Review:** Fable as well, for the key handling.
- **Dep:** 6.0e, 6.17; decision 12. **Estimate:** 1.5 weeks (6.0e
  needed no fallback); the workspace build behind `kreivo` first.

### M3b acceptance

- **Gates:** the kit's standalone `wasm32v1-none` build and its sync
  check; the mock passing G1–G18; the client passing them through the
  mock; `ci-full`.
- **Handoff:** the design goes to the Kreivo teammate when this plan is
  committed; the kit follows at 6.16, the vectors and the mutation lists
  at 6.17.
- **Deferred Kreivo gates,** for when the teammate's pallet lands, named
  here so they are not lost; until (1) and (2) pass, the `kreivo` venue
  stays unselectable in production configuration (6.17b):
  1. G1–G18 pass in the teammate's pallet mock runtime, and the `fees`
     vectors in Kreivo's runtime tests;
  2. `just e2e-kreivo` on a Kreivo dev chain with the real client:
     register, add an authority, anchor near a window's boundary (the
     `WindowInFuture` wait), submit, a repeat, a refusal, an `anchored`
     read;
  3. the vendored tree's sync check in Kreivo's CI;
  4. the teammate's weights, with the in-Wasm mutation sweep as a
     `#[benchmark(extra)]`;
  5. a review of `ChargeSpaceFee` as a runtime-wide change, Kreivo's own.
- **What the mock proves, and what it cannot:** it proves the client's
  encode and decode against our reading of the design, its state machine,
  and that the design's rules run with the real `judge` over the real
  fixtures; it cannot prove FRAME's actual bytes under the real prefix,
  the hold and provider semantics, who pays under the live pipeline,
  Kreivo's timestamp lag, block capacity, or the envelope against the
  teammate's metadata. The deferred gates cover those.
- **Reviews:** an Opus milestone review, then a push.

## M3c: the prover worker, the JAM service, end to end

### 6.18 The prover worker and the reproducibility gate

- **Files:** `node/prover` (new, `vos-node-prover`), linked by the node
  behind a `prover` feature; `node/venue`; `pvm/proof/src/constants.rs`;
  a `program-id` tool (`vosx program-id <elf> <method>`).
- **Design:**
  - the role is the leader of the agent whose record it is; a failover
    re-proves at most the statement in flight;
  - a node-local job table, `id → queued | proving | proved(proof) |
    submitted | accepted | refused(code) | dead`, and a watermark per
    agent;
  - for each `Attest` with a window: the `Statement` from the record (pin
    E), its id; skip it as dead when its anchor would pass `MaxRootAge`,
    by the venue's time (pin D's rule),
    before the proof ends;
  - re-run traced on `witness_input` (the arguments ‖ served at a cut);
    the output and the io-hash checked against the record; segments,
    leaves, folds and the masked wrap; the proof into the blob store;
    `Proven { id, proof }` back to the agent;
  - wait for the anchor at the space's venue; submit through the space's
    `VenueClient` (the model venue here; Kreivo's from 6.17b; JAM's from
    6.19); `Repeated` counts as accepted; a backlog report.
- **The reproducibility gate (carried):** the program ids of the window
  kernel, the predicate and `balance`, `H_fold`, and the wrap's roots (28
  and 39) as repository constants, recomputed in `test-proof` under both
  feature sets and, through the `program-id` tool, on aarch64 (`just
  repro-aarch64`, under qemu-user or an ARM host). It pins the known
  programs' constants; it does not make a submitted id trustworthy: a
  venue or installer trusts an id only by recomputing it from the blob
  (6.8's review: an id computed over an unchecked wiring is a malicious
  verifying key for that id).
- **Tests:** a restart mid-proof leaves one proof; a duplicate submission
  is accepted once; a leader change; a dead statement skipped; an io-hash
  mismatch refused.
- **Gates:** at L = 10 min, one 16 GiB prover keeps up with three window
  statements a window (about 180–210 s each [est]) and the `balance`
  statements; the constants equal everywhere. If throughput fails, the
  prover-time levers carried from slice 5 (ALU padding, WITNESS_INPUT in
  the entry class, a leaf over several small segments) become a step.
- **Dep:** M2, 6.13, 6.15. **Estimate:** 2–3.5 weeks.

### 6.19 The JAM statements service (F)

- **Files:** `pvm/proof/statement/service` (new, `vos-statement-service`),
  built for riscv64em-javm like the default agent; the JAM-only host's
  harness (`statement/tests/support/jam.rs`) gains accumulate;
  `pvm/runtime/src/refine_host/jam.rs` (`fetch` priced by GP 0.8.0's
  per-kind table, `definitions.tex`'s C_Y, in place of the 10 + 40 a KiB
  fit); `node/jam/src/builder/fit.rs` (a package's payload within CE
  133's 204,800 B as well as W_B);
  `node/venue`'s JAM client through `node/jam`; **new tooling** in
  `node/jam`: deploying a second service beside the default agent (or
  alone) in `testnet.sh`, and a client that submits `Register`, `Anchor`
  and `Submit` items and reads the verdicts back.
- **Design:**
  - work items `Register`, `Migrate`, `Anchor`, `Submit { statement,
    proof }`: the statement in the `Submit` item's payload and the proof
    (≤ 256 KiB) as its extrinsic, read by `fetch` case 4, since JAM-NP
    CE 133 caps a package at 204,802 B [6.0b, measured]; submitted
    through PolkaJam's `submitWorkPackage` RPC with its extrinsics
    (`jamt item` takes none); the fallback the payload, with a JAM proof
    cap of at most 196 KiB − |statement|;
  - **refine** verifies an anchor's or a registration's ed25519 signature
    against the key it names, and runs pin F's stateless checks and the
    proof for a statement; it outputs a `Verdict` (≤ 48 KiB a report);
  - **accumulate** holds the spaces (genesis, keys, range), the anchors
    (`Last`, equivocation), `Seen`. For an anchor it checks the signer
    refine named against the space's registered keys (refine reads no
    state) and applies pin D's anchor rule with the slot's time
    (`slot × 6 s` from JAM's genesis time) before storing it. For a
    verdict it checks the roots anchored and the id unseen, and records.
    It prunes anchors and rooted `Seen` entries past `MaxRootAge`;
    rootless entries never expire (pin F). `MaxRootAge` is never raised
    in place; a raise is a migration that first prunes anchors older than
    the old bound (pin F);
  - **a replay's cost on JAM** (6.5's review): refine reads no state, so
    it cannot check `seen`; a replayed statement costs a full refine
    (about 110M gas) before accumulate refuses it `6`. The defence there
    is the package's core-time cost to whoever submits it, not `seen`;
  - **an undecodable statement** is code 1 in the `Verdict`, as at the
    pallet (`final-verify.elf`'s harness reports it `BAD_PAYLOAD`);
  - accepted program ids (and their venue-bound flags) are constants,
    changed by redeploy; `VenueId` per pin D;
  - **the agent's cut rows on JAM**: one `cut(w)` leaf a window in the
    service's state, never deleted until 6.14's pruning rule lands, and
    at most `MAX_CUTS` new adjacent leaves a package;
  - the service carries none of `final-verify.elf`'s test modes (mode 2,
    the anchor vectors, reports `ACCEPT` with no statement); otherwise
    accumulate records a verdict only when its `code` is 0.
- **Ops note (6.12's cuts):** a replica catching up by log across many
  windows writes one undo row per pending cut for each committed write it
  replays, and builds each cut in turn; by snapshot it does none of
  this. The runbook says so; 6.14 decides whether a node-local cap
  bounds it.
- **Tests:** first, a 256 KiB extrinsic submitted, refined and read;
  every fixture judged alike on the JAM-only host; anchors, an anchor
  signed by an unregistered key, equivocation, migration; a default-agent
  batch over 200 KiB of payload split by the builder; a rootless replay
  past `MaxRootAge` refused; a PolkaJam testnet run (`just
  jam-statements-testnet`): deploy, register, anchor, submit the masked
  fixture, read the verdicts back.
- **Unaligned loads** (6.4's review): legal on JAM's PVM, so the service's
  target may take `+unaligned-scalar-mem` for its decode and verify gas,
  if 6.6 has not measured it.
- **Gates:** refine ≤ 150M gas a statement (6.0b: 118.7M [measured]);
  PolkaJam's refine gas equal to the JAM-only host's for one statement;
  accumulate ≤ 2M gas a report; the service under 4,000,000 bytes, its
  only size bound (512 KiB binds nothing here: the service may cross it
  freely, with ed25519, the items and accumulate; 6.5's verifier-only
  guest is 523,362 B); a package within CE 133's 204,802 B; the guest's
  `.bss` (a 64 MiB arena and a 1 MiB stack) within JAM's refine memory;
  PolkaJam v0.8.0 pinned (sha256 `e90c8ccd…`).
- **Dep:** 6.0b, 6.5, 6.10. **Estimate:** 2.5–3 weeks (the new deploy
  tooling takes the upper bound).

### 6.20 The carrier audit (R7)

- **The carriers:** `Attest` and work results, `RefinePayload`, the JAM
  anchor chain and work reports, `Resume` inputs (served witnesses), blobs
  (proofs), logs and tracing, the worker's job table, Kreivo extrinsics
  and JAM work items, the tests' `target/tmp/wrap/` writes, `CPU_DUMP`
  and every environment-driven debug output.
- **Gate:** in a full run of 6.21, a byte search over every carrier that
  leaves the prover role finds no segment, leaf or fold proof, no served
  row, no plain hash of private arguments, no step count, memory root or
  register beyond φ9..12; the debug outputs exist only under
  `debug-internals`. `SECURITY.md` gains the table of what leaves.
- **Dep:** 6.18, 6.19. **Estimate:** 0.5–1 week.

### 6.21 End to end

- **`just e2e-chain`, the on-chain leg:** a three-node space with
  `balance`, the window actor, the representative and the worker,
  anchoring on the JAM statements service on a PolkaJam testnet (6.19's
  tooling):
  - masked statements accepted;
  - a venue-bound rootless statement accepted at its venue and refused at
    another (`0x7`); an unbound one accepted at both; each replayed past
    `MaxRootAge` refused (`0x6`).
- **The Kreivo leg, against the mock:** the space registered and its
  authorities added with 6.17b's `vosx space venue` tooling, then
  anchoring and submitting through `KreivoVenue` over the mock transport,
  its sovereign account paying within its budget; then the space migrates at window k from the
  mock to the JAM service: a statement at w ≥ k accepted at JAM and
  refused at the mock (`0x5`).
- **The gate for Kreivo is the mock end to end.** The same leg on a
  Kreivo dev chain (`just e2e-kreivo`, the subxt transport) runs when the
  teammate's pallet exists; it is not a gate of this slice.
- **Measured:** latency from `B_w` to acceptance at each venue, against
  pin D's `L/2 + D + t_prove + inclusion`; gas per statement on JAM; the
  deposits and fees the mock charged the sovereign account; the worker's
  throughput.
- **Gate:** every verdict as expected; latency ≤ L + D + t_prove + 30 s.
- **Dep:** 6.17b, 6.18, 6.19, 6.20. **Estimate:** 1–2 weeks.

### 6.22 Acceptance, and the code-quality rest from slice 5

- **Gates:** `slice-gate`, the checker loop, `just e2e-chain`, the
  kit's sync check.
- **Rows measured:** the masked wrap per statement (from `test-proof`'s
  own runs); the statements' rows,
  steps and proving; the JAM service's gas and size; the worker's
  throughput; the cut's cost.
- **Reviews:** the end review (Fable); the code-quality review (Opus); the
  cleanup steps below.
- **The code-quality rest from slice 5, all of it (decision 13).** The
  items of `research/slice-5/quality-review.md` that 5.16b–c left, each checked
  against the code at the step's start (an item a slice-6 step already
  removed is recorded as gone), folded as separate behaviour-preserving
  commits, proof bytes and fixtures unchanged unless named:
  1. **item 13's rest:** the compiler's `shape::chip` (25 constants) as
     one table in `vos_wire::records` beside `SEGMENT_CHIPS`, which
     `chips!` and the compiler both read;
  2. **R5's rest:** the row view on the interaction side
     (`ComponentTrace`), and the program-memory consumer's flag sums;
  3. **item 11:** gone at 6.9: `observed_step` was deleted with the
     refine-bundle path, and `TracingPvm::step` is the one step recorder;
  4. **item 14:** one `chips_of_mask` for the six mask-to-components
     selections;
  5. **item 15:** the preprocessed commit and twiddles built once
     (`verify_preprocessed_trace` over `program_commitment_on`,
     `prove_on` over `mix_statement_header`; recair's duplicated twiddles);
  6. **item 18:** the CPU relation bag as an owned `Lookups` struct
     implementing `ComponentLookupElements`, the draw order kept (the
     program ids are the guard);
  7. **item 19:** Blake2b's two `CompressionColumns` impls and
     `BoundaryColumn` generated by one `macro_rules!`, the column order
     kept;
  8. **item 20:** `classify_opcode` as struct literals with the category
     flags derived after the match, with an all-opcodes equality test
     against the old table;
  9. **item 21:** `CPU_DUMP` a generic dump over `C::ALL_VARIANTS` under
     `debug-internals`, or deleted (6.20 already gates it);
  10. **item 22's rest:** one `check_continuity` for the verifier's three
      chain-continuity loops;
  11. **item 23:** `pub` → `pub(crate)` for vos-pvm-recair's, poseidon2's
      and the compiler's functions with no outside user; `verify/recursion.rs`
      moved into vos-pvm-recair if its only users are there;
  12. **item 24:** one options struct for `prove_impl`'s chain; the
      `_immut` → `_immut_min` forwarders dropped from
      `BuiltInProverComponent`; recair's `HeaderWords` fake `Channel` as
      `statement_header_words()`;
  13. **item 25:** `Blake2bRecord` as `Blake2bCall`; `P2Hash` ↔ `Digest`
      by `From`; the BLAKE2b call's register list once; the 28-bit
      ordering decomposition once (`memory.rs`, `register_memory.rs`);
      `refine_codec`'s `encode_*` copies gone at 6.9;
  14. **item 26:** the CPU columns `Phi10/11/12/7` renamed
      `HPtr/MPtr/TLow/Flag`;
  15. **item 28's rest:** bare format numbers in tests and docs named by
      their `format::` constants;
  16. **item 32's rest:** the stale docs still standing (the "Kunekt actor
      runtime" header, the "producer-only" and "dormant" notes, the
      optional-chip count, the missing files cited);
  17. **item 33:** the 65 `// ════` banners; the `alloc` import through a
      crate prelude instead of 26 `#[allow(unused_imports)]`;
  18. **item 34:** the small idioms: the empty-trace early returns, one
      `MIN_LOG_SIZE`, `ilog2` over f64, one max-log-size constant for four,
      `MemoryLayout` out of `memory_page.rs` with a `#[repr(u8)]`
      permission, `array::from_fn` in `agent/tree`'s hash, named `Entry`
      tags in `encoded.rs`, `Probe.input`, named `leaf_terms` constants,
      the precompiles crate's needless `blake2b` feature;
  19. **item 35:** the long functions split (`leaf::deep`, `derive::kernel`,
      `compile::program::lower`, `DeepPlan::new`, `verify_rest`;
      `verify_refine_bundle_authenticated` gone at 6.9) and
      `Derived::derivation(elf)` for the four `Derivation::new` sites;
  20. **the two removals:** the relabel seam for the retired formats 18
      and 19 (with its test); the fuzz target `final_verifier_mutate`'s
      `Grow`/`Shrink`/`Clear` as one variant, 6.7's corpus regenerated
      after it.
  21. **6.9's leftovers:**
      - the runtime's observed refine path, the deleted collector its only
        caller: `RefineContext::run_observed` with `RefineObservation`,
        `RefineHostPhase`, `RefineMachineIdentity`,
        `InnerMachines::invoke_observed`, `InnerMachineObservation`,
        `Machine::continue_observed`, the `Option<Observer>` through
        `refine_host`'s `dispatch`, and their tests; `Machine::resume_observed`
        and `Interpreter::run_observed` stay (`pvm/bench` uses them);
      - `with_stack!`'s `ChannelKind::Blake2s` arm routed to `$unbuilt`, no
        format naming the channel; the Blake2s variants of `ChannelKind`,
        `StarkProofAny` and `Commitment` stay until the next segment
        format's successor, as removing them shifts 35's postcard indices;
      - before master: `spikes/s5-attestable` and
        `spikes/s5-precompile/harness` deleted (they call the deleted
        refine API).
  22. **A store layout version** (6.11's review): a row in the node
      store's system partition naming the keyspace layout, which
      `Fjall::open` refuses on a mismatch, so a store written before a
      layout change (6.11 moved committed rows under `0x03`) fails to open
      instead of hiding its rows.
  23. **The decode's allocator** (6.4's review): format 39's decode costs
      about 3.7M gas on the JAM-only host, most of it the guest's
      allocator over the proof's 1,012 column vectors (Stwo's shape), not
      the layout; a venue's allocator is the remaining lever.
- **Then the slice's own cleanup:** the Opus code-quality review of slice
  6's code, folded the same way.
- **Docs:** `proving.md` draft 6, `core-model.md`, `identity-and-authority.md`,
  `kreivo-pallet.md`'s superseded note, `clerk-across-spaces.md`, per
  `doc-fixes.md`; `slice-6-progress.md`, "Slice 6 accepted".
- **Estimate:** 3.5–5 weeks (the reviews 2–3, the slice-5 rest 1.5–2).

## Where the carried items land

| carried from slice 5 | where |
|---|---|
| masking the wrap, R1–R8 | 6.1–6.6; R7 at 6.20 |
| the fixed-layout decode | 6.4, in format 39 |
| Blake2b through `0x400` and Kreivo's `blake2_256` | deferred (decision 4) |
| fixtures regenerated, the transition both ways | 6.5 |
| F2, the venue binding | pins D–F; 6.13, 6.17, 6.19, 6.21 |
| the recursion AIR's forgery gates | 6.8 |
| adversarial venue fixtures | 6.5; the vectors G7 |
| panic-freedom by construction, fuzzing in CI | 6.7; the sweep's mutation lists to the teammate (6.17) |
| the reproducibility gate | 6.18 |
| Kreivo's dependency path | the kit and its sync check (6.16) |
| format 36 | retired, 6.9 |
| the pallet P0 and P1 | the design (6.16), the mock and vectors (6.17), the client (6.17b); the pallet is the teammate's |
| format 32 reserved | nothing to do |
| prover-time levers | conditional on 6.18's gate |
| C-DJUMP, the ledgers' 2^27 gap, the BLAKE2b pointer near 2^32, refine slices' page permissions | stay recorded; the audit's scope |
| the external audit | scope frozen at M2's acceptance (decision 14) |
| the code-quality rest | 6.22, all of it (decision 13) |

## Risks, and the gate that retires each

| risk | gate | when |
|---|---|---|
| a forgery accepted by the recursion AIR forces a successor to format 32 and a re-pin everywhere | 6.8, from the first day, before any venue pins an id | M2 |
| DIVERGENCE-012 falls, leaving the masked wrap under 80 proven bits (76.98 by powers) | 6.1's Fable review; fallback a batching-phase PoW ≥ 4 bits or blowup 8 with 41 queries | 6.1 |
| the zero-knowledge argument rests on R1, R2, R4 and the 8-column R; the statistics find only gross leaks | 6.6's gates with their power stated, and Fable's transcript review; the audit before value | 6.6 |
| a column miscount leaves format 39's bits wrong | 6.2's shape from the built components | 6.2 |
| the masked prover's time (×2.6–2.9, Blake2b Merkle at lifting 22) | 6.3's gate; packed salts (−2 s [est]); the wrap is about 2–5% of a window statement | 6.3 |
| the in-kernel prologue costs more than estimated | 6.0a, before the keyspace changes | 6.0 |
| the inline served overflows a work result or a JAM package | `Limits::served` per target, an at-cut attest weighing 2, `cap.rs`'s asserts, JAM's served inside CE 133 | 6.13 |
| the keyspace change breaks VOS ≡ JAM or replication | 6.11's equivalence tests and the checker loop; Fable | 6.11 |
| the cut, the `undo` rows or the held build fail under a crash or a failover | 6.12's acceptance tests, the first written before the code; the checker loop; Fable | 6.12 |
| the representative's close and the paths' return under a failover or a skewed clock | rows keyed by w (pin D); `Closed` and the re-cut (pin E); 6.14's tests | 6.14 |
| a deadline between parties read from a space's clock | pin D's rule: venue time only; reviewed in 6.14, 6.17 and 6.19 | M3 |
| a rootless statement accepted again after its `Seen` entry is pruned | pin F's rule, tested at `MaxRootAge + 1` at every venue (G9) | 6.5, 6.17, 6.19 |
| the teammate's pallet diverges from the design | the conformance vectors G1–G18 and the mutation lists; the Kreivo leg rerun on a dev chain when the pallet lands | 6.17, after the slice |
| the design's §13 questions answered otherwise | the mock and the client follow the recommended defaults; another answer regenerates the vectors and touches only `calls` | 6.16–6.17b |
| the node cannot reach Kreivo (no chain client in the workspace) | 6.0e's probe; 6.17b's subxt transport; fallback raw JSON-RPC | 6.0e, 6.17b |
| key custody of the nodes' sr25519 keys | decision 12 (one per node, no balance); 6.17b's Fable review | 6.17b |
| a compromised authority drains the sovereign account at block speed | the spend budget per window, refused before inclusion (design §7; G13) | 6.17 |
| an anchor refused as `WindowInFuture` near a boundary and lost | the client reads the venue's time first, waits and resubmits (design §9; G4; 6.17b) | 6.17b |
| a registration resubmitted with another `start_window` | the window in the registration digest, and bounded (pin D; G1) | 6.10, 6.17 |
| the `kreivo` venue used before the pallet meets the vectors | unselectable in production configuration until the deferred Kreivo gates (1)–(2) pass | 6.17b |
| a JAM package over CE 133's 204,802 B is refused at submission (statements and the agent's builder) | the proof as an extrinsic, measured first; `fit.rs`'s payload bound; `fetch` per-kind prices | 6.19 |
| the worker lags the window cadence | 6.18's throughput gate; L bounded below by it; the prover-time levers | 6.18 |
| a masked format iteration re-pins every venue | 39 lands once at 6.4, before 6.17 and 6.19; any later change takes a new number | 6.4 |
| randomized proofs against byte-for-byte fixtures | the seeded test seam and its build check (pin C) | 6.3, 6.5 |
| an unread or private value leaks through a carrier | 6.20's byte search over every carrier | 6.20 |

## Estimates

| | weeks |
|---|---|
| 6.0 spikes, probes and docs | 1.5–2 |
| M2 line (6.1–6.6) | 5–7.5 |
| M2 beside the line (6.7–6.9) | 3–5 |
| M2 acceptance | 0.5 |
| M3a (6.10–6.15, 6.14b and acceptance) | 9.5–15 |
| M3b (6.16, 6.17, 6.17b and acceptance) | 4–5.5 |
| M3c (6.18–6.21) | 6–9.5 |
| acceptance, reviews and the slice-5 rest (6.22) | 3.5–5 |
| **slice 6, engineer-weeks** | **33–50** |

- **The critical path:** 6.0a → 6.10 → 6.11 → 6.12 → 6.13 → 6.14 → 6.15 →
  6.18 → 6.20 → 6.21 → 6.22, about **16–26 weeks** of calendar with three
  tracks.
- **Beside it:** M2 (6.1–6.9), about 5.5–8 weeks on its line, must land
  before 6.18; M3b from 6.10's end (6.17 also after 6.5), 4–5.5 weeks,
  reaching 6.21 with slack; the JAM service (6.19) from 6.5.
- **Review latency** (Opus on every step, Fable on seventeen) is not in
  these figures.
- **Against `proving.md` §11's 14–20 weeks for M2 and M3:** that row did
  not count the space identity, the keyspace change, the cuts, the
  representative or the anchors (M3a, 8.5–13.5), the Kreivo kit and
  client (M3b), nor the carried items (6.7–6.9, 3–5; the slice-5 rest in
  6.22). The Kreivo pallet, its weights and fees left the slice for the
  teammate. M2's line itself is spike 6a's 2–3 weeks for its steps 1–6
  plus the gates and the reviews.

## Decisions

### Taken by the owner

**Before the slice:**
- **The scope:** M2 masks the final wrap only, kept generic for slice 7's
  device proofs; M3 as above; the carried items in this slice; slice 7 is
  mobile; the Clerk follows slice 6.
- **The process:** Opus on every step, Fable on the marked ones; `just
  check` per step, `ci-full` and the loop at milestones; acceptance per
  milestone; the slice's end review, code-quality review and cleanup.
- **The fork's pushes** after a Fable review, never forced.
- **From `proving.md` §12:** STARKs only; one proof per statement;
  Blake2b-256 for the final proof; the Kreivo pallet after the recursion.

**On 2026-10-19, on draft 2:**
1. **`SpaceId`:** the genesis hash,
   `BLAKE2b-256("vos/space/id" ‖ SCALE(genesis))`; the clock frozen in the
   genesis; no controller in it, a founding key binding one at each venue
   (pin D).
2. **The window clock:** Unix time at a fixed cadence; L per space in
   [2, 60] minutes, default 10; the close's delay D = min(L/5, 2 min);
   `MaxRootAge` 24 h. **With its rule:** any time logic between parties
   uses the venue's chain time, never a window number or the space's
   clock; the space's clock schedules only its own cuts (pin D). And the
   latency it implies: authorization instant, trustless settlement about
   `L/2 + D + t_prove + inclusion`, parallel proving the lever below it,
   not in slice 6 (pin D).
3. **Format 36:** retired, and the refine-bundle proving path deleted;
   the default `prove` and the bench on 35 (6.9).
4. **The Blake2b hook:** deferred, a lever for when ref_time binds.
5. **The agent root:** committed rows under `0x03`; the VOS agent root
   equals JAM's node (6.11).
6. **History:** no tree history past a cut (W1), and spans by a carried
   per-pair commitment at the venue (S3); `RootKind { Space }` only.
7. **The space root:** the representative agent; anchors signed by one
   registered node key; the controller rotates the keys (6.14; the
   node's side of rotation, 6.14b).
8. **F2:** migration ranges for rooted statements, and a per-program
   `venue_bound` flag checked on `public_args[0..32]`; no `vos/io/v2`.
9. **Kreivo's dependency path:** the verifier stack vendored into Kreivo
   with a sync check against a VOS tag; frame-contrib and crates.io later.
   An input to the design and the kit (6.16).
10. **Governance:** `ProgramsOrigin` the Virto community with a Root
    override, a 7-day delay, an `EmergencyOrigin` pause, signed
    submitters, `Record` only, a rootless statement's `Seen` entry never
    expiring. A default of the design.
11. **Fees:** normal length and weight fees on `submit` and `anchor`, and
    a refundable deposit on `submit`, released on acceptance and forfeited
    on refusal, except a repeat (code 6), which releases it, since two
    nodes can race (the owner confirms in `spaces-pallet.md` §13.4); paid
    by the space's sovereign account for its authorities through the
    design's `ChargeSpaceFee`, within a spend budget per window. A default
    of the design.
12. **The nodes' Kreivo accounts, redirected:** the Kreivo pallet becomes
    a general spaces pallet (to replace pallet-communities later), each
    space with a sovereign account that pays, and a map of its current
    authorities, the nodes' own sr25519 keys; pallet-pass and anonymous
    authentication by proof are later stages. **Kreivo's scope in slice 6
    is the design and the kit:** no pallet code from VOS; the node's client
    tested against a mock of the designed interface; the on-chain end to
    end on the JAM service only, the Kreivo leg when the teammate's pallet
    exists (6.16–6.17b, 6.21).
13. **The code-quality rest from slice 5:** all of it in slice 6, in
    6.22's cleanup.
14. **The external audit:** its scope frozen at M2's acceptance; the
    engagement after slice 6, before any value rides on a proof.
15. **The Clerk's doc:** renamed `clerk-across-spaces.md`, its slice
    number set when it is scheduled, with a header on what changed.

**Open in the design, not blocking slice 6:** `spaces-pallet.md` §13
(how the sovereign account pays, the anchor key, the sovereign's
derivation, the deposit on a repeat, the amounts, the controller's form,
the name and index, the Kreivo leg's timing, the communities fold-in,
anonymous authorities), each with a recommended default for the teammate
and the owner to confirm. The mock and the client follow the defaults.

**Owner actions, not decisions:**
- **A1:** naming the Kreivo teammate: the design is available at this
  plan's commit, the kit at 6.16, the vectors at 6.17;
- **A2:** a machine whose cores report L3, for PolkaJam's recompiler;
- **A3:** 5.6's phone run (slice 7).

### Settled by the evidence, the owner's to override

- **Format 39 at shape A** (pin A): blowup 32 and 24 queries over blowup 64
  and 20 [measured: ×1.41 memory against ×2.79, ×1.2 verify against
  ×1.13].
- **Variant (c), not (a) with unpairing:** the recursion AIR is degree ≤ 3
  with paired logup; no re-LDE [measured].
- **Salts as columns,** 8 M31 a tree, not inside the fork's lifted hasher.
- **R2's boundary re-cut is trivial for the wrap:** its public sum is the
  24 words and `u`.
- **The FRI mask R at 8 columns, with no production rank check** (pin C;
  Fable's review of draft 1): R3 holds except with probability about
  2^-155, for about 64 MiB of prover heap, 384 B of proof and under 1% of
  gas over 4 columns [est]; the check survives as a test on the small
  circuit.
- **The JAM service's proof as the `Submit` item's extrinsic,** the
  statement in its payload (6.0b: CE 133 caps the package at 204,802 B,
  below pin F's 256 KiB; a uniform bound at every venue).
- **Opt-level 3 for the venue's verifier** (6.0b: `s` +39.6% gas, `z`
  ×2.59, for bytes no cap needs).
- **The masking's code** in vos-core's `recair`, `recair-air` and
  `final-verifier`, over the fork's public API.
- **The fixed-layout decode** in format 39.
- **Production venues accept masked final formats only;** 28 is a test
  format.
- **The JAM venue a dedicated service:** an actor in the default agent
  breaks `MAX_HANDLER_GAS` (100M against 118.7M) whatever its bytes (the
  masked-only verifier alone is 500,205 B, under the 512 KiB program cap
  [6.0b]), the 2 KiB message cap, and has no preimage access. Refine
  verifies; accumulate checks anchors and repeats (its 10M gas a report
  cannot verify).
- **The kernel returns the statement's parts at its halt,** and the
  record holds them (Fable's blocker).
- **The served witness inline in the `Resume` input** under
  `Limits::served` (6.0a: no host call reads a blob at refine; a blob path
  needs a new input kind, a lookup and JAM provisioning).
- **The `Cut` marker timed at the leader's clock** (finding 6).
- **The representative's rows keyed `(agent, kind, w)`** (findings 3, 11).
- **The worker is the agent's leader,** its job table local, the venue's
  repeat check the only coordination (finding 13).
- **The open window is not anchored:** a venue takes an anchor only for
  `w < now_w`, by its own time (pin D).
- **The statement's shape as built:** the id without the format,
  `ProgramId` as 8 M31, no shape class.
- **Every value-moving handler two-sided, and counterparties anchoring at
  one venue** (finding 9): recorded for the Clerk.
