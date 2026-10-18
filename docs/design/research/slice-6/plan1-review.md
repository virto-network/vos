# Review: slice 6 plan, draft 1

Reviewer: Fable, 2026-10-19. Read-only. Against `slice-6-plan.md` and
`doc-fixes.md` (stage), the evidence in `tmp/s6/`, `vos-core` at `31b7938e`,
the spike worktrees (`.worktrees/s6-mask`, `~/src/virto/kreivo-s6-spike`).

## Verdict

**Ready after fixes.** The plan is the right shape: the pins are concrete, the
evidence is real (the masked wrap measured on the pin, the verifier linked into
a Kreivo runtime, the security tool extended), my design-round review's blocker
and all nine majors are folded in as specifications and tests, not mentions,
and every carried item has a home. What remains are one missing component on
the critical path (the node's Kreivo client), a handful of protocol details a
step would hit on its first day, one decision the plan should settle now
instead of deferring (the FRI mask's width), and one owner decision framed
without its implementation cost (fees). None changes the architecture.

Findings are numbered; severity is blocker / major / minor; each has a fix.

---

## A. Masking soundness and zero knowledge (question 1)

### A1. [major] Decide the FRI mask's width now: 8 columns, no rank check

Both variants are sound, and a retry loop leaks nothing: the rank of R's DEEP
coefficients is a function of the transcript the verifier itself can compute,
so conditioning the accepted transcript on it is a public event a simulator
reproduces; its probability (about 2^-31 per attempt) does not depend on the
witness, so neither attempt counts nor timing carry witness information. But
the 4-column variant puts a conditional argument, a retry path that no test
will ever exercise in production (one firing in 2^31 proofs) and a
`prove_values` replay into the audit's scope, for a saving of 4 columns at
level 17: about 64 MiB of prover heap (of 3.45 GiB), about 384 B of proof and
under 1% of gas. The 8-column variant's failure is about p^-5 ≈ 2^-155 with
no check, no retry and a two-line argument (eight uniform QM31s span M31^4
unless an 8×4 matrix has rank < 4).

**Fix.** Pin A: R = 8 columns; composition tree width 20; drop R3's prover
check from the production path (keep `fri_mask_coefficients_independent` as a
test over the generic small circuit, so the argument is exercised). Drop 6.0c,
or keep it as the hour that confirms the cost. Move the item from "unless 6.1's
review prefers" to "Settled by the evidence". R1's retry stays (it also never
fires at h = 256 against 80 rows, but it is the completeness guard the
zero-knowledge argument rests on, and its refusal at h = 64 is tested).

### A2. [major] Leakage gate 2, "a simulator from the public inputs alone", is undefined

A true simulator for a STARK transcript programs the random oracle; nobody
will write one in 6.6's 1–1.5 weeks beside six other gates. What the spike-2
plan meant, and what is testable, is witness indistinguishability: proofs of
two different valid witnesses with the same public inputs are
indistinguishable field by field, which is gate 3. Gate 2 as written will
either be skipped or faked.

**Fix.** Define gate 2 as "the honest-prover distribution does not depend on
the witness": the masked fields of N proofs of witness A against N of
witness B (gate 3's pairs), plus a control that the *unmasked* prover fails the
same test (it does: the zero witness opens to zeros). Say what each test has
power to find at N = 2,000 with Bonferroni over tens of thousands of fields
(per-field α ≈ 10^-8: only gross leaks, a smoke test). State that the
zero-knowledge *argument* is the review's (R1 on every proof, the programmable
random-oracle model), and the statistics are a regression guard.

### A3. [major] Pin the masked reference shape from the built components

6.1 pins 39 at 146 / 82 from `MASKED_WRAP_REFERENCE`, which spike 6b §4.7 calls
"a design estimate until R2 is built" (12 main and 8 interaction blinding
columns, +2 constraints). 6.2 builds the components a week later; nothing in
the plan recomputes the shape from them, as `the_reference_shapes_are_the_segment_airs`
does for segments. A column miscount would leave the registry's bits wrong by
a fraction of a bit without any test noticing.

**Fix.** 6.2 tests: "the masked wrap's security shape derived from the built
`MaskedComponents` equals `MASKED_WRAP_REFERENCE`, and its count is 82.69–82.70";
the derivation from the components' own layout (k = 4N whole, j = 1), never
through `framework_access`' split-subtracting helpers (6.1 already says so for
the tool).

### A4. [minor] The seeded seam's production check must ignore dev edges

Pin C's check "refuses the feature in the dependency tree of every `node/` and
`agent/` crate", modelled on `check-no-faults` (`cargo tree --workspace -e
features -i vos-node`). The fixtures generator is an integration test of
`vos-pvm-proof`, whose dev-dependencies will enable `seeded-masks` on recair;
`cargo tree` includes dev edges by default and the check would fail, or be
loosened until it passes nothing.

**Fix.** `cargo tree -e features,no-dev -i vos-pvm-recair` (normal and build
edges only) per production binary (`vos-cli`, the agent, the prover feature),
and a second assertion that `debug-internals` does not imply `seeded-masks`.
Also state that `MaskRng::Seeded` is unreachable from `MaskRng::new` in any
build: the seeded constructor exists only under the cfg, the hedged one has no
parameter that selects it.

### A5. [minor] Levels are per component; the pin's wording names the tallest

Pin A and pin B say "trace masks at m+1 = 16". `p2` is 2^14, `h8` 2^11: each
masked column sits at its own n_c + 1, lifted; 16 is `qm31`'s. The spike's
`committed_log_sizes` already does this. Write "each component's columns at
n_c + 1 (16, 15, 12), the composition at m+2 = 17, the lifting 22".

### A6. [minor] What the masked verifier leaves to Stwo, named

Pin B is right that `verify_masked` never calls `core::verifier::verify`; the
spike's `masked.rs:131` still calls format 28's `check_shape` before its own
checks, and `verify_values` → `FriVerifier::commit` derives the round list
from the largest column (17 → [3,3,3,2]). Both are fine; 6.4 should list them
as the two Stwo-side facts the format pins (tree widths; the FRI round list),
each with a test, so the audit can see where the trust boundary is.

## B. Format and pin hygiene (question 2)

Checked: 38 is the fixtures' `SUCCESSOR` ("a number no format holds",
`fixtures.rs:313`) and stays unassigned; 40 goes to `RETIRED`; `RETIRED` is
`[24,25,26,27,29,31,33,34]` today and its test asserts no retired number is
registered, so adding 40 is consistent (B1). Format 32's guard is the stale
fixture test, passing on the spike branch. The preprocessed root's equality is
pinned by its own test. Refusal codes 1–6 and `0x100 | err` are used; 7 is free.

### B1. [minor] Say why 40 is retired though never registered

`RETIRED`'s doc says the retired numbers "named earlier forms"; 40 never named
anything that shipped. One sentence in A.4 (doc-fix 30 has it) and in
`format.rs`'s table: "40 was spike 6a's blowup-64 shape; retired so no later
format takes a number a measured proof once carried."

### B2. [minor] `Format.bytes` lives in `vos-pvm-proof`; the layout lives in the verifier

`vos-pvm-final-verifier` does not depend on `vos-pvm-proof` (it pins its own
`FORMAT`, `CONFIG`, `LOG_SIZES`). The new `bytes: ProofBytes` field is read by
the prover and the registry tests; the verifier's `layout.rs` is the layout.
Add to 6.4's tests the existing pattern: a `vos-pvm-recair` test that the
verifier's pinned constants (format number, config, widths, `FixedLayout`)
equal the registry's entry for 39.

## C. Roots, anchors, `&self` (question 3)

My design-round review's items, checked against the pins and steps:
blocker 1 (the kernel returns the statement's parts, the record holds them) →
pin E's `KernelReturn` and `Attest`; major 2 (transport, caps) → served by hash
through the blob path, `Resume { request, served }`, 6.0a's reading with an
inline fallback that keeps `cap.rs`'s asserts; 3 (the leaf race) → rows keyed
`(agent, kind, w)`; 4 (the representative's own cut) → pin D; 5 (crash and
failover ordering) → 6.12's three rules and acceptance tests; 6 (the marker at
the leader's clock) → 6.12; 7 (`venue_bound` flag) → pin F; 8 (clock frozen) →
pin D; 9 (two-sided handlers, co-location) → pin D and the settled list; 10–17
→ 6.11's migration list, `MaxRootAge` alone, the worker's role, fail-fast at
request time, 6.0a first, `served` from gas. All folded correctly. The blob
peer-fetch the served path needs exists (`dispatch.rs` `serve_blobs`/`take_blob`;
entries name their blobs in the payload header, `store/entry.rs`), so 6.0a's
reading should confirm quickly.

### C1. [major] The `space_path`'s return to the requesting agent is unspecified

Pin E: "the requesting agent's leader assembles `Served` with the
representative's `space_path`". 6.14: the path is "generated by the same held
build, only for agents that asked". How it reaches the requesting agent's
leader is not said. The representative is replicated on ≥ 3 nodes; the agent's
leader need not host a replica of it, so "read it locally" is not available in
general. This is the same kind of data-flow gap as my blocker 1, and 6.14 hits
it on day one.

**Fix.** The representative's leader sends, after `cut_rep(w)`'s build and in
the same hook that signs the anchor, one pair message per pending agent:
`Closed { w, rep_root, paths: Vec<(request, space_path)> }`, exactly-once on
the existing pair. Applied by the agent, it lands as a replicated row keyed by
request; the leader then assembles `Served`, stores the blob, and proposes
`Resume`. Add to 6.14's tests: a representative leader change between the
build and the send (the new leader re-sends; the agent's apply ignores a
duplicate).

### C2. [major] Rootless statements and `Seen`'s expiry: a replay after 24 h

6.16: `Seen: id → expires`, pruned past `MaxRootAge` with the anchors. A rooted
statement replayed after pruning fails `Unanchored`. A *rootless* statement has
no anchor to fail: once its `Seen` entry is pruned it is accepted again, and
`Record` records it twice; any later handler with an effect double-applies.
The design's "a rootless fact is true twice" was about two venues, not two
times.

**Fix.** Pin F and 6.16: `Seen` entries of rootless statements never expire
(their count is bounded by the fee per submit; a deposit if the owner wants a
bound), or every rootless program is `venue_bound` and its handler is
idempotent by `id` with the handler's own storage as the long-term set. State
the rule, test the replay at `MaxRootAge + 1`, and apply the same to the JAM
service's accumulate.

### C3. [minor] A pending request whose window the representative missed

6.14 tests "an agent that misses the close" and "the representative down across
three windows" but states no expected behaviour for the *request*. With X1, a
representative returning after several boundaries cuts them all at one version
that excludes the agents' queued `AgentRoot` rows, so no `space_path` exists
for those windows and `S_w` anchors a stale table.

**Fix.** Pin E: a pending request of window w whose `Closed { w }` does not
arrive by `cut(w+1)` is re-cut at w+1 automatically (its `rows_proof`
regenerated at the new cut; the old one dropped), at most K times (2), then the
workflow sees an error. Make it 6.14's expected outcome for both tests.

### C4. [minor] The model venue needs a migration range

6.5's adversarial case "a window outside the migration range (`0x5`)" and pin
F's "anchored (within the venue's migration range)" need `model::Policy` to
carry `range: (from_w, until_w)`. 6.5 says `Policy` gains the venue id and the
per-program flag; add the range.

### C5. [minor] `vos_pvm_precompiles::RootRead.kind` is a `u8` too

6.10 changes `vos-statement`'s `RootRead.kind` to `RootKind`. The kernel-side
type (`pvm/proof/precompiles/src/io.rs:22`) has `kind: u8` and the io-hash is
computed over it; the SDK's prologue states `RootKind::Space`. Add the
precompiles crate to 6.10's files (a `RootKind` with a `u8` wire form, refused
when unknown), or state that the kernel side keeps the byte and the SDK maps.

### C6. [minor] `vos-anchor` "depends on `blake2` only" but encodes SCALE

`SpaceId = H("vos/space/id" ‖ SCALE(genesis))`, `Served` SCALE, `Anchor` on the
wire. Either hand-roll the codec as `vos-statement/src/codec.rs` does (say so:
"SCALE by hand, canonical, as `vos-statement`"), or take `parity-scale-codec`
with `default-features = false` (one more crate in Kreivo's vendored tree,
already in its lock). Pick one in 6.10.

### C7. [minor] Define the two-sided-handler rule where the pallet reads it

Pin D says every value-moving handler is two-sided or escrow-funded and slice 6
admits `Record` alone. Put it in 6.16's handler trait doc and `SECURITY.md`,
so the Clerk's handler is written against it.

## D. Kreivo (question 4)

Vendoring (c2) with a sync check is right; the spike shows zero unification
work and a stable toolchain. Weights by `frame-omni-bencher` 0.24.0 with the
owner's A1 for the reference machine: right. Pushes: owner's word. Panic sweep
inside the Wasm as `#[benchmark(extra)]`: right.

### D1. [blocker] The node's Kreivo client is not a step

6.14 defines `trait VenueClient { id, anchor, submit, anchored }` and builds
`ModelVenue`. 6.19 builds the JAM client "through `node/jam`". 6.18 "waits for
the anchor at the space's venue; submits"; 6.21 anchors and submits on a Kreivo
dev chain. **No step builds the Kreivo `VenueClient`:** a Substrate RPC client
in the node (subxt or equivalent, none in the workspace today), signing
`anchor` and `submit` extrinsics from a funded account, tracking inclusion and
the `Accepted`/`Refused` events, reading `Anchors` for `anchored`, handling the
`Repeated` refusal, metadata pinned to the runtime. It has an external
dependency (subxt against stable2606 metadata), a key-custody question (which
Kreivo account each node holds, and how), and it sits on the critical path
before 6.21. This is exactly the late surprise the owner forbade.

**Fix.** Add **6.17b `node/venue/kreivo`** (F for the key handling): subxt at
the stable2606 line, a `KreivoVenue: VenueClient`, the account key from the
node's key store, event-driven verdicts, a dev-chain integration test (anchor,
submit, repeat, refusal code mapping), 1.5–2 weeks, dep 6.17; and **6.0e**, a
1–2 day probe that submits one extrinsic to Kreivo's dev chain from a Rust
client and reads storage back, so the dependency's shape is known before M3b.
Add owner decision **15**: the Kreivo accounts (one per space's representative
and worker, or one per node), their funding, and their key custody on nodes.
Add 6.17b to the estimates (M3b 5.5–8.5) and to the critical path (+1.5–2).

### D2. [major] Decision 11 (fees) names options without their cost; Kreivo already has the cheap one

The recommended option, "a length discount for `submit` and `anchor`", is not
a stock FRAME knob: `LengthToFee` is uniform (`ConstantMultiplier`,
`config/currency.rs:59`); a per-call discount means a custom
`OnChargeTransaction` or transaction extension in Kreivo's fee pipeline, a
runtime-wide change outside the pallet with its own review. Kreivo's runtime
already wires `pallet_skip_feeless_payment` (`SkipCheckIfFeeless`) and
`pallet_gas_transaction_payment` (gas tanks, index 17), so `#[pallet::feeless_if]`
on `anchor`/`submit` with a community gas tank, or a deposit refunded on
acceptance, are each a few lines in the pallet.

**Fix.** Reframe decision 11 with four options and their cost: (a) charge as
is (0 work; about 0.43 UNITS a proof, 144 anchors a day); (b) `feeless_if` +
gas tank (pallet-only; the space's community funds a tank; spam bounded by the
tank); (c) a deposit on `submit` refunded on acceptance (pallet-only; a refused
proof pays); (d) a length discount (runtime fee pipeline change). Recommend (b)
or (c), not (d), for slice 6.

### D3. [minor] M3b has no acceptance section

M2 and M3a have one; 6.17's gates stand in for M3b's. Add "M3b acceptance:
Kreivo's suite with the sweep, the size gate, the laptop weights recorded, a
push of `vos-statements` only with the owner's word".

## E. JAM service (question 5)

The dedicated service is right: 118.7M gas against `MAX_HANDLER_GAS` 100M,
538,683 B against 512 KiB, 2 KiB messages, no preimage access as an actor;
refine verifies under G_R = 5e9, accumulate records under G_A = 10M. The split
of pin F's checks (refine: stateless checks and the proof; accumulate:
`anchored`, `seen`, the registered key) is right. The JAM-only host meters GP
0.8.0's per-basic-block gas (`pvm/runtime/src/gas_cost.rs`), so the measured
numbers are the right model; 6.0b's PolkaJam 0.8.0 probe is the right check.

### E1. [major] Decide the proof's transport on JAM by evidence in 6.0b

6.19 fixes "the proof a preimage (`historical_lookup`, ≤ 256 KiB)", inherited
from `final-verify.elf`'s harness. On a live chain a preimage must be
solicited by the service's accumulate, provided, and become available before a
refine can look it up: a two-package protocol with its own latency and
failure modes (6.19's testnet run would discover them). A work item's payload
is bounded by the bundle (W_B = 13,791,360 B); a 163 KB proof rides in the
`Submit` item itself with no protocol step. Preimages buy only deduplication
across packages, which a proof never needs.

**Fix.** 6.0b: read GP 0.8.0's work-item payload bound and PolkaJam's handling
of a 170 KB item; if it fits, 6.19 carries the proof in the payload and the
preimage path stays for the harness only. Record which.

### E2. [minor] Accumulate checks the anchor's signer is registered

6.19: refine "verifies an anchor's signature against the key it names".
Refine reads no state, so it cannot know the key is one of the space's;
accumulate must check the signer against the space's registered keys before
storing the anchor, and apply pin D's anchor rule with the slot's time. Say so
in 6.19's accumulate list.

### E3. [minor] Deploying a second service is new tooling

`node/jam/testnet.sh` deploys the default agent as one service. 6.19's testnet
run deploys the statements service beside it (or alone) and needs `node/jam`'s
client to submit `Register`/`Anchor`/`Submit` items and read verdicts. Name it
in 6.19's files and keep the estimate's upper bound.

### E4. [minor] 6.21's JAM leg: which venue

The migration test "the space migrates to the JAM statements service at window
k" needs a live JAM venue inside `just e2e-chain`. Say whether that is a
PolkaJam testnet in the same run (heavy) or the JAM-only host harness as the
second venue, with the PolkaJam leg in 6.19 alone. Recommend the latter.

## F. Steps (question 6)

Every step has a goal, files, tests, gates with thresholds, deps and an
estimate; Fable marks the soundness, protocol and layout steps. The carried
list is complete: masking R1–R8 (6.1–6.6, R7 at 6.20, R5 cheaply in 6.2), the
fixed-layout decode (6.4), fixtures and the transition both ways (6.5), F2
(pins D–F), the forgery gates (6.8, from day one), adversarial fixtures (6.5),
panic-freedom and CI fuzz (6.7, 6.17's sweep), the reproducibility gate
(6.18), Kreivo's path (6.16), format 36 (6.9), the pallet (6.16–6.17), format
32 (nothing), the levers (conditional), the recorded-unfixed (audit scope),
the audit (13), the code-quality rest (12).

### F1. [minor] 6.5 should carry F

Pin F's check order, the accepted set and the adversarial cases are protocol;
a wrong order (the proof before `seen`, say) is a DoS vector every venue
inherits. Mark 6.5 F, or fold its review into 6.6's.

### F2. [minor] 6.15's test actor signature does not compile

`at_least(&self, #[public] account: Commitment, #[public] threshold: u64,
salt: [u8; 16], account: Account)` names two parameters `account`. Rename the
first `commitment`.

### F3. [minor] 6.20 is on the critical path

6.21 depends on 6.20 (0.5–1 week); the critical-path sum omits it. With D1's
6.17b the path is about 16–26 weeks.

### F4. [minor] 6.6's "the production build has no seam" is a build check, not a test

Say it is A4's `cargo tree` assertion in `just check`, so nobody tries to
write a runtime test for it.

## G. Estimates and the critical path (question 7)

30–47 engineer-weeks and 14–23 calendar weeks with three tracks are plausible
for the steps as written; the plan roughly doubles spike 6a's 2–3 weeks for
M2's line, which is right once gates and reviews are counted. Review latency
(Opus each step, Fable on 13) is not in the calendar figure; say so. With D1
and F3 the path is about 16–26 weeks.

**The riskiest remaining unknowns**, in order: the cut, `undo` rows and held
build under crash and failover (6.12), with the representative's close (6.14),
which is new distributed-protocol surface; the node's chain client (D1,
unscheduled); DIVERGENCE-012 (6.1, first in M2: right); the in-kernel prologue
(6.0a, first: right). 6.12 cannot move before 6.11 without building the held
build twice, so its place is right; but its first acceptance test (a crash
between the cut and its proofs, with the checker) should be written *before*
the implementation, as the step's brief, so the implementer builds to it.

## H. Owner decisions (question 8)

The fourteen are the right ones, each with options and evidence. Changes:

- **Order.** Decisions 8 (format 36, 6.9 in M2) and 9 (the Blake2b hook,
  scopes 6.4 in M2) block work in weeks 2–4; decisions 3–7 block M3a steps that
  start later. Ask 1, 2, 8, 9, then 3–7, then 10–14.
- **Settle by evidence:** the FRI mask's width (A1); the JAM proof transport
  (E1). Decision 9 could also be "settled, the owner's to override": nothing in
  slice 6 verifies as a PVM guest on a VOS host.
- **Add:** decision 15, the Kreivo accounts and key custody (D1); decision 11
  reframed (D2); the `Seen` rule for rootless statements (C2) as a line under
  decision 10.

## I. Doc fixes (question 9)

Spot-checked 32 line references in `proving.md`, 9 in `recursion-air.md`, 18 in
`core-model.md`, 9 in `identity-and-authority.md`, 14 in the Clerk's draft (`clerk-across-spaces.md`):
every one lands on the quoted text. The replacement numbers match the spikes
(115.8–118.7M, 160–163 KB, 3.45 GiB, ×1.41, +75.7 KiB, 3.99 ms, 0.43 UNITS,
538,683 B, 82.70, 8.5–13 and 18–29.5 weeks). Two amendments: proving item 15
and recursion item 5 should carry A1's outcome (8 columns) rather than "the
variant per 6.1's review"; proving item 20 should add C2's `Seen` rule for the
JAM service. Add a doc-fix for `proving.md` §6: the node's Kreivo client (D1).

## Summary table

| # | severity | fix |
|---|---|---|
| D1 | blocker | add 6.17b `node/venue/kreivo` + 6.0e probe + decision 15 (accounts, custody) |
| A1 | major | R = 8 columns, no production rank check; settled by evidence |
| A2 | major | define leakage gate 2 as witness indistinguishability; state its power |
| A3 | major | 6.2 recomputes the masked reference shape from the built components |
| C1 | major | `Closed { w, rep_root, paths }` pair message carries `space_path` back |
| C2 | major | rootless `Seen` never expires (or venue-bound + idempotent handler) |
| D2 | major | decision 11 reframed with costs; `feeless_if` + gas tank or deposit |
| E1 | major | 6.0b decides proof transport on JAM (payload vs preimage) |
| A4–A6, B1–B2, C3–C7, D3, E2–E4, F1–F4 | minor | as above |
