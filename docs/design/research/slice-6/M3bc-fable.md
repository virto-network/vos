# M3b + M3c milestone review (Fable)

`vos-core` at `68570481`, 2026-10-23. Read-only. Scope: 6.16, 6.17, 6.17b
(parked to mock-only by decisions 12c/12d), 6.18, 6.19, the load-sensitive
hardening and the writer-stall bound (decision 16), 6.20, 6.21. Judged
against pins D–F of `slice-6-on-chain.md`, `spaces-pallet.md`, the owner
decisions and `SECURITY.md`'s table.

Method: my own pass over the protocol core (`vos-statement`, the JAM
service's refine/accumulate/state/items/config and guest entry, `vos-venue`'s
trait, model, JAM client and anchor queue, `leader/close.rs`,
`anchor_keys.rs`, the representative, the prover worker and job table, the
node's prover host, the JAM live client, the load-hardened tests); two Opus
sub-reviews, one on the Kreivo mock and vectors, one on the carrier audit
and feature gating, whose load-bearing claims I verified in the source
before adopting them.

**Verdict: accept after fixes.** No path was found by which a wrong
statement is accepted or a forged, replayed or cross-venue anchor lands at
either venue. The defects are on the node side (anchors that stop being
retried, right statements refused for good), in what the carrier audit
claims versus what it searches, and in what the conformance vectors leave
unpinned for the teammate. All are bounded fixes; none reshapes the
protocol.

## Findings

### High

**H1. A pallet that ignores a format's or program's activation window
passes every conformance vector.**
`node/venue/src/kreivo/mock/mod.rs:948-955`, `:1104-1108`;
`node/venue/conformance/spaces.json` (every pre-state stores `Formats[39]`
and the fixture programs as `Active { from_ms: 0, until_ms: None }`; G7's
codes 2 and 3 come from absent entries; G11 and G16 write future-dated
entries and never submit against them). Scenario: the teammate's `submit`
checks `contains_key` and not `from_ms`/`until_ms`; G1–G18 pass; in
production a program scheduled under the 7-day `ProgramsOrigin` delay
(decision 10) is live at once, and a delayed removal never takes effect.
Fix: steps that submit the fixture while `Formats[39].from_ms > now`
(expect 2) and while `Programs[p].until_ms <= now` (expect 3), then after
activation (accepted); regenerate with `just conformance`.

### Medium

**M1. A queued anchor is never replaced, re-signed or alerted on; a key
rotation that completes after the hand-over loses the window for the
leadership.**
`node/venue/src/queue.rs:498-508` (`push` is `or_insert`);
`node/venue/src/jam.rs:110-125` (`Key`, `Unregistered`, `Suspended`,
`Signature`, `Item` → `Fate::Again(120 s)`, no alert, forever until `Age`);
`node/venue/src/kreivo/venue.rs:546-554` (`Answer::Configuration` →
`Again(window_length)` with the same signature);
`node/host/src/leader/close.rs:289-295` (`Ok(Queued)` → `true` →
`anchored.insert(window)`: the leader never hands the window over again
in this leadership). Scenario: the leader signs window w with K1 (listed)
and queues it; the venue's clock has not closed w (`Open`, retried a slot
at a time); meanwhile the controller, following the documented rotation
order, adds K2 and removes K1; the queued anchor is now refused `Key` and
retried every 2 minutes with K1's signature for up to 24 h; the leader
believes w settled (`seed_waiting` runs once per leadership); w is a gap
unless leadership moves, and every read's statement rooted at w dies
`0x5`. Pin D promised "anchoring again once its listing changes, or a
window later" — the queue (6.17b's L5 fold) swallowed that path. Fix:
(a) `push` replaces an entry whose `signer` differs (newest signature
wins); (b) a `Fate::Resign` (or `Again` with a reason) for key/registration
refusals that removes the entry and surfaces the window through
`VenueClient` (e.g. `unsettled(space) -> Vec<u64>`), which the leader's
`anchor_wait` recheck reads to move the window back to `unanchored`; (c)
`JamSend` alerts on every non-`Open` refusal as the Kreivo client does.
Test: rotate the key between `push` and the first `Done`, assert the
window lands under K2.

**M2. The leader treats `Unregistered` (and every refusal but `Open`,
`Key`, `Suspended`) as settled for good; a space registered after a window
closed loses that window until leadership moves.**
`node/host/src/leader/close.rs:320-324`; `node/venue/src/kreivo/venue.rs:
768-771` answers `Unregistered` from its cached read. Pin D explicitly
admits a late registration (`start_window ≥ now_w − MaxRootAge/length`),
and the Kreivo client answers `Unregistered` until its first refresh
after the registration lands. Scenario: windows 0–2 close while the
controller is still funding the sovereign and registering; each is
handed over once, refused `Unregistered`, and marked `anchored`;
`seed_waiting` ran at the leadership's start, so nothing retries them;
the replicas still hold their cut roots (`CUT_KEEP`), but no anchor goes.
Fix: `Unregistered` joins `Open`/`Suspended` as "wait" (alert once, keep
in `unanchored`); and re-run `seed_waiting`'s venue check for the windows
in `anchored` once per window length, so a `Queued` that silently died
(M1) is also taken up. Test: register after window 1 closes; assert 0 and
1 anchored by the same leadership.

**M3. The worker refuses a right statement for good on venue codes that
are transient.**
`node/prover/src/worker.rs:577-587` (`Refused(code)` is final for every
code but 6); `node/venue/src/jam.rs:282-292` maps the service's
`Outcome::FAILED + error` (`0x1001` refine out of gas, `0x1002` a panic,
`0x10ff` an undecodable verdict) to `NotAccepted::Refused`. Scenarios:
(a) a space suspended for an equivocation between the worker's
`anchored()` read and accumulate: `0x5`; after the controller resumes it
the roots are anchored again (pin D: "go dark while it is suspended"),
but the job is `Refused(5)` for ever; (b) `anchored()` true at the
finalized block, accumulate three slots later past `B_w + MaxRootAge`:
`0x5`, correct, but also (c) a package refined out of gas because
`refine_gas` was shared across a fuller package: `0x1001`, and the
statement is never sent again. Fix: codes 5 and `≥ 0x1000` go through the
`retries` backoff until `dead()` (the deadline is the right bound); only
1–4, 7 and `0x1xx` are final. Test: a venue answering 5 once then 0.

**M4. There is no operator path to a venue: `Config::venue` is set only by
the harnesses; `vos node run` has no venue option; the prover worker starts
only with a venue (`node/host/src/prover.rs:273`).**
`node/host/src/node/config.rs:61`; `node/cli/src/args.rs` (no venue);
`node/cli/src/jam/statements.rs` is a deploy-and-drive tool, not a node's
configuration. The e2e also switches venues at migration through a
test-only `Migrating` client (`node/host/tests/chain/venues.rs:212-229`);
a production node has one venue, so a migration would need a restart with
the new venue, after which statements rooted before `k` can never find
`anchored()` true at the new venue and die at `MaxRootAge`. This is a
readiness gap, not a protocol one: 6.21's claims hold for the harness.
Fix before the slice closes, or scope it explicitly: either `vos node run
--venue jam --jam-url … --service … --config …` building `JamVenue::new`
(the code-hash and genesis checks already exist), or a line in the plan's
6.22 that the JAM venue is wired by the harness only and the operator
path is slice 7's. For migration, a `VenueClient` that routes by window
range (old venue for `w < k`, new for `w ≥ k`) is the production shape
of `Migrating`; carry it with an ops note that the old venue stays
configured until its last pre-`k` statement is accepted.

**M5. The carrier audit searches less than it records.** Verified in the
source:
- (a) **The "gas a re-run left" needle is a constant.**
  `node/prover/src/masked.rs:160` pushes each boundary's `state.timestamp`
  into `Internals::steps` during the watch; `:196-197` push the run's
  total and the lengths after; `node/checker/src/carriers/needles.rs:291`
  takes `steps.first()` as the run, so the needle is `2^32 − 1` (segment
  0's initial timestamp is ≥ 1), and its forms are dropped by the
  distinct-bytes filter. 6.20's L3 claim is not covered. Fix: a
  `run_steps` field (or push the total first), the `Internals::steps` doc
  made true, and a unit test building needles from a known `Internals`.
- (b) **The JAM watch sees a package only after `submitWorkPackage`
  returns.** `node/jam/src/live/package.rs:220-230`: `self.call(...)?`
  before `watch(...)`; `rpc.rs` has a 60 s read timeout. A package the
  node took but whose answer timed out is on chain and unwatched, and
  `Statements::land`'s second-core resubmission goes the same way; its
  bytes are then searched only at `Recorded` strength in the chain's log
  and database, exactly the reduction 6.21's review justified by the watch
  being complete. Fix: watch before the call, and assert in the run that
  every outcome the service holds belongs to a watched package.
- (c) **`Reach::Recorded` also exempts the service's own output.** The
  testnet's log and database hold the statements service's guest-log
  lines and accumulate writes, VOS code computing on the package, not only
  the chain's counters; a step count decoded by the service and printed
  in decimal is caught nowhere (small numbers' byte forms are already
  below the distinct-bytes floor). Fix: the service's storage dumped over
  RPC as a `Leaves` carrier; the chain's layout constants (run 4's
  collision) excluded by value, as entry-state registers are, rather than
  the whole number class.
- (d) The masked wrap's own randomness and mask-column commitments are
  not needles (`vos-pvm-recair` `tree.rs:258-266`: `final_watched` is
  outside the watch seam); and the audit runs only happy paths, while a
  prover panic's message reaches stderr through the default hook
  (`worker.rs:460`) and `TreeError`'s `Debug` is formatted into
  `ProveError::Failed` (`masked.rs:250-260`). Fix: a `Built::Wrap`
  observation; one audited run with an injected failing and a panicking
  proof, or a redacting panic hook on the prover thread.
The feature gating holds: `check-no-debug-internals` compares each
package's enabled features whole over `-e no-dev --target all`, for the
workspace, `vos-cli --features prover`, the agent and the final verifier's
Wasm workspaces, and scans the `vos` binary for the five variable names;
`vos-node` has no default features, `vos-node-prover/prove` does not imply
`disclosing`, and every `debug-internals`/`watch` enable is on a dev edge.
Two small gaps: the scan reads the debug binary, and
`vos-statement-service --features pvm-guest` is not checked.

**M6. The conformance vectors and the design leave the teammate gaps a
compliant pallet can fall into.** (Beside H1.)
- (a) Pin F's length bounds (statement 64 KiB, proof 256 KiB, genesis 2
  KiB) have no vector; the only `undecodable` step is G11's handler byte.
  Fix: over-bound and at-bound submits and a register, expecting
  `undecodable`.
- (b) `spaces-pallet.md` §6.5 requires `on_idle` "bounded by the remaining
  weight, with a cursor", §5 names no cursor item, and §10 with G17 pins
  "every raw key whose value changed": a pallet keeping a `PruneCursor`
  under the pallet's prefix fails G17. Fix: name the item in §5 and exclude
  it in the vectors.
- (c) `Budget`'s key and layout are never pinned (`conformance/mod.rs:424`
  drops `Budget` writes; no pre-state holds one), while the client reads
  it before paying (`kreivo/venue.rs:669`); G13 never exercises the
  released deposit's credit-back. Fix: pin the key and `window` field,
  mask `spent`; one G13 step with an accepted submit leaving room for one
  more.
- (d) No reference runner: `conformance/mod.rs:601`'s replay is the mock's;
  "passes G1–G18" is self-certified by whatever harness the teammate
  writes. Fix: a FRAME-agnostic runner in the kit, or VOS reviews the
  harness (state it in §9.1).
- (e) For the port (M3b's deferred gate 2, not this milestone): the
  client marks an anchor held on a best-block `Anchored` event
  (`venue.rs:506-508`), `last` only ever rises (`:411-413`) and
  `anchored()` answers from the cache (`:850`); §9.1's "reads at finalized
  blocks only" must cover `held` and `last` too, or a reorg makes the
  worker submit against a retracted root and forfeit the deposit. And
  after a `Lost` answer, any pool `Invalid` but `Stale` returns to the
  caller (`transport.rs:253`), who later re-signs with a fresh nonce while
  the first may still land: add "already imported", "temporarily banned",
  "priority too low" to §9.1 mapped to `Lost`.

### Low

**L1.** `Leader::anchor_due` settles a waiting anchor unsent past
`MaxRootAge` by the node's clock (`close.rs:224-233`), not the venue's
(`VenueClient::time`); a node clock jumped a day forward drops every
pending anchor. Fix: `venue.time()` when it answers, the node's clock
otherwise.

**L2.** `Statements::land` resubmits the same items to core 1 after
`timeout/2` (`node/jam/src/live/statements.rs:125-147`) and returns
whichever package's outcomes it reads first, in core order; two `Control`
items of one nonce then report `Nonce` for a control that applied. Within
one package, two items of one payload share an outcome id and the second
overwrites the first. Harmless to the node's worker (one statement a
package; 6 counts as accepted); wrong for the tooling's answers. Fix:
prefer the outcome with code 0 across the packages; refuse duplicate
payloads in `submit`.

**L3.** Migration is one-way per venue and a space cannot register again
(`accumulate.rs:186`, `:230`; the mock the same): a space that leaves a
venue can never return without a new genesis. And any single founding key
registers the space at a venue under a controller of its choosing
(`refine.rs:115-123`); one compromised founder squats the space at every
venue it has not reached yet (`Again` thereafter). Both are design-level
and consistent with pin D's text; record them in pin D and carry (a
registration co-signed by the controller, or by a founders' quorum, is
the lever).

**L4.** The worker proves at-cut attests alone (`worker.rs:311` filters
`window.is_some()`): rootless `Kind::Stating` statements have no
production prover; 6.21 proved its rootless ones in the harness. By
6.18's text; record it as carried.

**L5.** Finished rootless jobs are never pruned (`worker.rs:283-287`:
no deadline); the table grows with every accepted rootless statement.
Prune finished jobs once the agent's watermark and compaction are past
their record.

**L6.** `JamSend` alerts on no refusal (part of M1); the Kreivo client
alerts on each. After M1 both should.

**L7.** From the sub-reviews, worth a line each: `assert_searchable` plants
only the first `Leaves` form of each needle (`audit.rs:141-147`), so per-
form detectability rests on `tests.rs`'s synthetic cases; `directory()`
swallows read errors and skips file names (`capture.rs:135,142`); node
disks are read before `cluster.stop`; Stwo's `info!(proof_size_estimate)`
is a size side channel beside the logged proof time and belongs in
`SECURITY.md`'s logs row; `resume` leaves the disputed window's first root
anchored (mock and model alike) and no vector pins it; `Options::per_submit`
defaults to one UNIT while a submit holds 1.5; the mock's `migrate` omits
`to != venue`; §9.1 cites "§7's ten extensions, in order" but §7 lists
none (the list left with `chain.rs`), and names `tests.rs` and
`cluster/kreivo.rs` as the ported transport's gate though both drive
`MockChain` internals.

**L8.** Ops notes: decision 16's bound (3 s at the defaults, the election
timeout's upper end) means a node proving on the leader's disk can hand
over every group it leads under a single slow fsync, then win them back;
the harnesses keep 5 s because their nodes share one disk. A JAM
registration's `genesis_ms` is `EPOCH_MS` (the common era) in both the
CLI and the harness, which is right for JAM's slot time; `JamVenue::new`
pins it through the configured block, so a wrong value is consistent on
both sides and only shifts `MaxRootAge` and the registration bound.

## The questions

**1. Protocol safety.** Forged anchors: refine verifies `verify_strict`
over `digest(venue)`, accumulate checks the signer against the space's
listed keys at its own time; a Kreivo anchor cannot land at JAM and a
replay is `Again`. Rotation: `Control` is nonce'd and venue-bound, at most
16 keys, a removed key's anchors `Key`; the JAM tests cover add, remove,
replayed add, resume only after both equivocators are delisted, and a
controller hand-over. Migration: `until = from_window` with `from_window
> Last`, `≥ next`, `≥ start`; `Range::contains` on anchors and on
`submit`; one-way (L3). `venue_bound`: `public_args[..32]` against the
venue in `admit`, refused `0x7` at a second deployment in 6.21. Rootless
replay: id = H(program ‖ NONE ‖ io-hash), the rootless `Seen` entry is
`u64::MAX` and never queued, so a replay is `0x6` at every venue (6.21's
replays past `MaxRootAge`). The refine/accumulate split: refine is
stateless (anchored true, seen false), outputs a verdict whose roots are
non-empty only on code 0, and accumulate accepts only code 0 after
`anchored` (registered, unsuspended, in range, fresh, held root equal) and
`seen`; a refused verdict is recorded as refused. Outcomes are keyed by
`H(package ‖ payload)` so no later package overwrites one (L2 within a
package). `Seen`: a rooted entry's expiry is the newest root's `B_w +
MaxRootAge`, queued by hour, dropped only after the hour; `fresh` is the
real guard, so the prune's order is immaterial; the service test shows a
rooted replay `0x5` and a rootless `0x6` after the drop. `MaxRootAge`: at
most `now − B_w ≤ 24 h` on anchor and on submit, `start ≥ now_w − 24h/L`
on registration; never raised in place (a constant of the deployed
code). A clock jump: JAM's slots are monotonic and 6.21 skipped a day of
epochs; a node's jump is M3a's alert plus L1. Verdict: no wrong statement
accepted, no forged or replayed anchor lands; a right statement can be
refused for good at the node (M3), not at a venue.

**2. The prover worker.** Exactly-once is by statement id with the
`proven` row kept first-only (`agent/default/src/refine/inputs.rs:176`),
every replica scanning its log into jobs, compaction held at the prover's
mark (at most 2^16 behind, then an alert), `Proving` re-queued at open,
`Submitted` resubmitted and a 6 counted accepted; only `leads()` (role,
not stopped, leading) submits; the leader-change test covers a proof
fetched from a replica and one proved again after `patience`. The table
is synced on every `put`; the watermark is buffered, which is safe since
the jobs it reads past are synced. The reproducibility constants are
pinned in `pvm/proof/src/constants.rs` and recomputed in `test-proof`
with and without `debug-internals`, and `just repro-aarch64` compares
`vos program-id` under qemu for the three programs and the three
circuits. Defects: M3, L4, L5.

**3. Privacy.** The audit is sound in structure (production code path,
case-sensitive Aho–Corasick, non-empty check per kind, a canary per
capture path) and the feature gating holds; it is weaker than recorded on
the four points of M5. The `Recorded` reduction is defensible once (b) and
(c) are fixed: then everything the chain was sent is audited whole as it
went, and the chain's own records add only their own numbers.

**4. The Kreivo handoff.** The mock follows the design closely and the
vectors pin the call bytes, event and error indices, storage keys and
values, the sovereign derivation, `Seen`'s expiry, the freshness and prune
edges, both-keys `resume`, the signed start window and the deposit's fate.
Not yet a sufficient contract: H1 and M6(a–d). The parked state is
honest: `kreivo-unvetted` and `selectable` survive only in history,
tag `0x10` is documented reserved, `KreivoVenue` builds only in tests;
the misleading bits are §9.1's two stale references (L7).

**5. Robustness.** None of the hardening loosened a property below what it
proves: `a_stale_leader_left_out_of_the_configuration_retires` still ends
in `retired(stale)` and requires an iteration where the stale leader led
beside the new one; the snapshot-stream test asserts on the stream the
follower answered and that none starts after its first chunk; `D + 30 s`
stays far inside a 120 s window; the leader-follows and resend helpers
retry only on `NotLeader`/`TimedOut`. `Config::stall_bound` derived from
`election_timeout_ms.1` is the right default (a stalled leader hands over
no sooner than a crashed one is detected) and the override keeps the
harnesses' 5 s; see L8.

**6. Readiness for 6.22.** Fix before the slice closes: M1, M2, M3 (node
liveness and a right statement's fate), M5(a)(b) (the audit's claims),
H1 and M6(a)(b)(c) (cheap generator and design edits that change what the
teammate can connect), and M4 as a decision (wire the operator path, or
name the JAM venue harness-only in the plan). Carry with a line in the
plan: M5(c)(d), M6(d)(e), L1–L8.

**Verdict: accept after fixes** — the protocol holds at both venues; the
fixes are to the node's anchor and submission liveness, the audit's
coverage, and the vectors' completeness.
