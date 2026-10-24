# Slice 6 end review (Fable)

`vos-core` at `bf895d27`, 2026-10-24. Read-only. The slice `31b7938e..bf895d27`:
M2 (the masked wrap, format 39), M3a/b/c (roots, anchors, `&self` reads, the
Kreivo design and kit, the prover worker, the JAM statements service, the
end to end) and 6.22 (the slice-5 rest, the layout version, the review
folds). Judged against the plan's pins A–F, the owner decisions 1–17 (taken
as settled), `SECURITY.md`'s table and the design docs.

Method: my own pass over the protocol core (`vos-statement`'s `admit` and
`judge`, the JAM service's refine and accumulate, `vos-anchor`, the venue
trait and helpers, `AnchorQueue`, the leader's anchoring and closes, the
worker's scan, prune and follow, the `check-no-*` table, the fixtures' and
vectors' history across 6.22) and five Opus sub-reviews (the masked wrap,
the on-chain protocol, the node, the carrier audit, the docs and the carried
list), each load-bearing claim of theirs checked in the source before it
appears here. Tags: [V] verified in source by me; [S] verified by a
sub-review and spot-checked; [I] inferred.

**Verdict: accept after fixes.** No path was found by which a venue accepts
a wrong statement or loses a right one for good while the space's anchor
keys are honest; the masked wrap's bits hold and are pinned by tests; the
folds of every earlier review are in the code. The defects are in what
happens once a listed anchor key is compromised (the honest node never
raises the evidence pin D relies on, and `resume` reinstates the disputed
root), in the node's prover worker under failover (statements dropped, not
re-proved), in what the carrier audit and `SECURITY.md` claim against what
they search, and in stale numbers and omissions in the docs and the carried
list. One gate is owed: the slice-gate tier has not run at the tip.

## Findings

### High

None.

### Medium

**M1. The honest node never sends the conflicting anchor, so a compromised
listed key equivocates without evidence or suspension.** [V]
`node/venue/src/kreivo/venue.rs:476-481`: when the client's last read has
`last >= window`, it answers `Window` and sends nothing unless the root is
in its own `held` (its own landed anchors; `refresh` never fills it).
`tools/jam-dev/src/venue.rs:150-162`: `JamSend::standing` answers
`Fate::Done`, unsent and unlogged, once `last >= window`.
`node/host/src/leader/anchor.rs:365-369`: the leader takes `Window` as a
refusal for good and settles the window. Only `ModelVenue`
(`node/venue/src/model.rs:288-295`) raises evidence, which is why every test
passes. Scenario: a replica's key is stolen while listed (or a replaced
replica's key was never delisted); at `B_w` the attacker anchors a root of
its choosing; the honest leader signs at `B_w + D`, up to two minutes later,
and its client swallows the anchor; no evidence, no suspension, no alert;
for 24 h statements over the attacker's root are accepted and the honest
ones at `w` refused `0x5` until they age out; repeatable every window. Pin D
says "anyone may submit the second signed anchor", and the honest leader is
the only party who will. Fix: a client whose venue holds the window reads
the held root; equal → `Again`; different → send the node's anchor as
evidence (the venue then suspends, as designed) and raise a distinct
equivocation alert; absent (a gap) → `Window`. The leader treats
`Equivocation` as an alarm of its own. Test: another listed key anchors
first; assert evidence and `Suspended` through both clients.

**M2. `resume` reinstates the disputed root.** [V]
`pvm/proof/statement/service/src/accumulate.rs:345-355` clears `suspended`
and `equivocators` and leaves the `0x02` anchor rows; `:363-397` then
accepts a statement over the held root (`!suspended`, in range, fresh, root
equal). The mock does the same (`node/venue/src/kreivo/mock/pallet.rs:155-177`).
The 6.22 close recorded this as "stays as documented, unpinned by a vector".
Scenario (after M1 is fixed, or a third party sends the second anchor): the
compromised key anchors `R_bad` at `w` first; `R_good` arrives second and
suspends the space; the controller delists both keys and resumes; `R_bad`
is anchored and fresh again until `B_w + 24 h`, so statements over the root
the controller just repudiated are accepted, and `R_good` can never be
anchored at `w` (a resend suspends again). No value rides on a proof in
this slice (decision 14), so this is carryable, but not as "as documented":
it is the owner's call, recorded in pin D, `spaces-pallet.md` §6 and
`proving.md` §7, and pinned by a conformance vector either way (today no
vector says what a post-resume submit over the disputed root does). Fix if
taken: on `Resume`, drop the held anchor of every window that has evidence
(the record would carry the disputed windows beside `equivocators`), so
neither root counts; G-vector: after resume, a submit over the disputed
window's root is refused `5`.

**M3. A replica that installed a snapshot and then leads drops the old
leader's queued statements.** [V path, I scenario]
`node/prover/src/worker.rs:341-344`: a scan counts an index whose record
`attests()` cannot read as `lost` and moves the watermark past it; a replica
behind the leader's `log_start` installs a snapshot and reads every index at
or below it as `None`, so no job is made. `next()` and `submittable()`
require `leads()` (`worker.rs:445-455`), so the old leader's `Queued` jobs
die with its leadership. `lost` is in memory, logged only while
`pending() > 0` (`node/host/src/prover.rs:322-326`). This contradicts 6.18's
"a failover re-proves at most the statement in flight". Nothing reaches
production yet (no venue is attached to the shipped node, decision 17), so
carry the fix; correct the claim now. Fix: make the unproved set
recoverable from replicated state (an "attested, unproven" marker per cut
the new leader scans), or have a new leader pull peers' unfinished jobs; at
least a distinct alert when a scan crosses `log_start`.

**M4. The worker's table does not stay bounded, and a missing kernel blob
stalls all proving.** [V]
(a) `worker.rs:297-324`: `prune` removes finished jobs and turns an aged job
holding a proof into `Dead`; a `Queued` or `Proving` job of an agent this
node does not lead is never touched, and `follow` (`:399-413`) moves it only
on a `proven` row, which a refused, dead or lost (M3) statement never gets.
Each such job keeps its `Attest`, `witness_input` included, after the log
entry is compacted. `SECURITY.md:421` ("each job's record until it
finishes") is therefore not true of these. (b) `worker.rs:494-496` and
`:347-350`: a job whose kernel blob is absent is picked again every step
until `dead()` (about 24 h; never for a rootless job), and the scan stops at
that record for good; kernels are pinned only while an installed instance
names them (`node/host/src/group/apply.rs:294-340`), so an agent upgraded
with statements of its old kernel queued loses them all. Fix: `prune` marks
any aged unfinished job `Dead` and drops jobs of agents this node no longer
runs once read past; pin each unfinished job's kernel under `NODE_AGENT`;
`next()` skips a job whose kernel is absent, refusing it after a bound.

**M5. A live run's fault text reaches the logs and a query's answer.** [V]
`node/host/src/pvm.rs:177-180` and `:218` format `ExitReason`'s `Debug` (a
page fault's address among them) into `Fault::Agent`; `node/host/src/group/apply.rs:232-236`
logs it at warn; `node/host/src/queries.rs:331` returns it to the caller as
`CallError::Failed`; an executor panic's message goes the same way
(`node/host/src/executor.rs:67-68`, `node/host/src/fault.rs:58-61`). The
redacting hook (`node/prover/src/redact.rs`) covers only stderr while a
proof is in flight, the audit runs happy paths only, and `SECURITY.md`'s
logs row does not name fault text. The replica's logs and an authorized
caller already hold the agent's state, so this is not the prover role
leaking; it is an unlisted carrier whose content is data-dependent. Fix:
log and answer the `ExitReason` variant alone and a static panic message
with its location; a row in `SECURITY.md`; later, one audited run with a
faulting kernel.

**M6. The carrier audit searches less than `SECURITY.md` says, and the floor
is undisclosed.** [S, floors read]
`node/checker/src/carriers/needles.rs:44-45, :89, :174-178, :293, :321, :370`:
byte needles need 8 bytes and 4 distinct; a number's forms need 4 distinct
bytes (most values below about 2^16 are dropped); step counts at most 255
or a power of two, single registers below 2^24 and row values below 2^24
are not needles. The test's rows are high-entropy by design
(`node/checker/tests/carriers/audit.rs:34-40`). `served()` drops the row
key (`needles.rs:362`) and only the served rows, not every row the run
wrote, are needles. What compensates: each value's salt and hashes, the
served-rows and witness blobs, the re-run gas needle. `SECURITY.md:397`
("every carrier's bytes are searched for the run's own internals")
overclaims. Fix now: state the floor and the compensations in `SECURITY.md`;
carry: served keys and every written value as needles, a small-value run.

**M7. Docs: numbers that contradict the docs' own current ones, and two
carried limits absent from the designs.** [S, spot-checked]
`docs/design/proving.md:1285` gives `wrap.proof` as 145,796 B (the file is
146,564; `:402` has it right); `:1299` gives 109.7M/109.8M gas where §3.5,
§10 and `recursion-air.md:753` say 79.3M; `recursion-air.md:680-682` still
shows spike 6a's masked figures (115.8–118.7M, 160–163 KB, 3.45 GiB) as
current. `SECURITY.md:405-422` lacks the JAM storage carrier (M5(c)) and its
`carrier_except`, the wrap-randomness needles, the panic redaction and
`ProveError::Failed`'s shape, all in `proving.md` A.5. L3 (one founder
registers the space anywhere under any controller) is in pin D only, not in
`spaces-pallet.md` §6.2 or `proving.md` §6/§7; L4 (no production prover for
rootless statements) is in the plan only, and `clerk-across-spaces.md:9-11`
overclaims against it (`node/prover/src/worker.rs:346` filters
`window.is_some()`). Fix: re-measure or drop A.6's column; label the spike
rows; bring `SECURITY.md`'s table to A.5; one "known limit" line each for
L3 and L4 where a teammate or auditor reads.

**M8. The `final-verify.elf` the justfile and `proving.md` call "the
production venue's" accepts without a proof in its `ANCHORS` mode.** [V]
`pvm/proof/statement/src/bin/guest/mod.rs:203-207`: a payload starting with
`ANCHORS` decodes a vector and returns `ACCEPT`, no proof read. The JAM
venue is `statement-service.elf`, which has no such mode (`service/src/lib.rs:39`),
and nothing deploys `final-verify.elf` as a venue, so no venue is exposed;
the hazard is the label (`justfile:399`, `proving.md:554`), and the plan
carries the mode's move (item 27) into the re-pin batch without saying why.
Fix now: call the ELF the harness's refine program; state the hazard beside
item 27 (or move the mode to `final-verify-test.elf` now: no test pins the
ELF's hash, so nothing re-pins).

### Low

**L1. The byte-for-byte guard of the masked prover did not run after the
`prove_once` split.** [V] `6a25314e` is #61 of the reviews-folded batch;
`just fixtures` ran after #40 and #44, `test-proof` last at `c77445d5`
before the batch; after #61 only `check`, `test-carriers` and `e2e-chain`
ran. The committed guard, `kernel fixtures::the_fixtures_are_the_generators`
(`pvm/proof/tests/kernel/fixtures.rs:192`), lives in `test-proof`. The
sub-review diffed the split and found the draw and transcript order
unchanged, and the record notes a manual hash comparison; the slice-gate
tier (`test-proof` at full N, five-minute fuzz) has not run at the tip (the
record's last is M2's). Fix: the slice-gate green at `bf895d27`, recorded;
consider a cheap seeded-hash pin of the small masked circuit in `check`.

**L2. No test pins the guest blobs' hashes.** [V] `final-verify.elf`,
`final-verify-test.elf`, `statement-service.elf` and the Wasm blobs are
built at check time and committed nowhere; 6.22's "every guest blob hashed
the same" is a manual procedure in the log. The fixtures' acceptance and
refusal tests guard their semantics; their identity (what a JAM deploy's
code hash is) is unguarded. Fix: a `blobs.lock` of the hashes checked by
`check-no-std`, re-pinned with the re-pin batch.

**L3. A root `cargo build` unifies test features into `vos`.** [S]
`node/checker/Cargo.toml` enables `vos-node/dump` and `vos-venue/kreivo` on
normal edges; the root manifest has no `default-members`; `cargo tree
--workspace -e no-dev` shows `dump`, `kreivo` and `vos-statement/fixtures`
in the graph. The `_forbidden` rows forbid these for `-p vos-cli` and
`-p vos-node` only (`justfile:251-301`), and no release recipe or Dockerfile
exists in this tree, so the shipped artefact is undefined. The code is dead
in `vos`. Fix: `default-members` excluding `node/checker` and
`tools/jam-dev`, or a pinned `just release` with gate rows for exactly that
build; `_debug-names-absent` reads a hard-coded `target/debug/vos`
(`justfile:241, 311`), so a set `CARGO_TARGET_DIR` could pass a stale file.

**L4. The pallet's signature semantics are unspecified.** [S, I on FRAME]
Every VOS verifier uses `verify_strict` (`node/venue/src/lib.rs:69-77`,
`refine.rs:77-82`, the mock); `spaces-pallet.md` §6 does not say strict.
`sp_io::crypto::ed25519_verify` is cofactored, accepting any message for a
small-order key. Fix: require strict verification, or refuse small-order
keys at `register` and `add_authority`; a vector with a small-order key.

**L5. The JAM dev client can wedge after a key is removed and re-added.**
[S] `tools/jam-dev/src/venue.rs:357-359` uses `queue.push`, which refuses
the same signer while the window is unsettled (`queue.rs:157-160`); the
Kreivo client uses `push_listed`. Dev tooling, liveness only; the pair is a
trap for any later client. Fix: `push_listed` once the finalized record
lists the signer.

**L6. Worker edges.** [S] (a) `inner.resume` starts the drivers before
`prover::start` sets `proving` (`node/host/src/node/open.rs:160-167`), so a
compaction in that window ignores the mark. (b) `MAX_ATTEMPTS` counts an
operator's kill mid-proof (`worker.rs:497-499`; stop waits for the proof,
`prover.rs:308-336`): three restarts refuse a right statement for good on
that leader. (c) A crash between `hold(true)` and `put(Proved)`
(`worker.rs:509-512`) leaks the first proof's pin. (d) `retries` and the
`MAX_RESUBMITS` counts are in memory. (e) A finished proof on a deposed
node is `Unrecorded` (`prover.rs:211-216`) and the new leader re-proves
from scratch; the all-cores proof is a likely cause of the 3 s writer stall
(L8), so leadership and proving can ping-pong. (f) `core-model.md:850` says
"a sync held past the stall bound"; the check is the oldest pending commit's
age, queueing included (`node/host/src/storage/mod.rs:329-334`).

**L7. The carried list's omissions and labels.** [S] Missing: item 5's lock
helper (`slice-6-progress.md:4189`), item 58's performance half (the table
read whole several times a step). Item 68 hides an owner call: `closes::stored(...).unwrap_or_default()`
at `agent/default/src/refine/inputs.rs:122` drops a report on a `Corrupt`
row silently (deterministic across replicas: a liveness gap, not a forgery
path); name it. Item 28 is correctly labelled a strictness fix and is not
reachable by a submitter (`natural` parses the host's arguments and
operands only: `statement-service.rs:229-232, 270-272`, `accumulate.rs:79, 83`);
say so. The "Where the carried items land" row "the code-quality rest |
6.22, all of it" overstates by item 18's two re-pin pieces. The plan's Docs
line names `kreivo-pallet.md`; the file is `research/slice-5/kreivo-pallet.md`.

**L8. Timelessness.** [S] Code comments are clean but for the carried
`ABOUT` string (`node/venue/src/kreivo/conformance/mutations.rs:323`, one,
not several). `core-model.md:708, :723` ("built at slice 6's 6.12/6.11/6.14"),
`spaces-pallet.md` at 8-10, 43-47, 145, 171, 678, 687, 778, 797, 969, 987
(step numbers and "M3b's deferred gate 2", in the one doc a teammate reads
without the plan; its open question 8 is settled), `recursion-air.md:722`,
`identity-and-authority.md:417` (a pin letter), `SECURITY.md:259, :275`.
`core-model.md` still heads itself draft 5 after `338e70df`.

**L9. Small inaccuracies.** [V unless noted] `MAX_VERDICT_BYTES`
(`service/src/lib.rs`) counts one byte for the roots' compact count; 64
roots take two (`codec::compact`, `0x40..`): `MAX_ITEMS` is unchanged at
17. `SECURITY.md` row 11 gives tree heights (20, 22); the preprocessed
tree is 21 [S]. `wrap::prove_masked`'s `tamper: FnOnce(&mut MainTrace)`
is a public, ungated parameter the production caller passes `|_| {}` to
(`pvm/proof/recair/src/wrap.rs:214, 219`) [S]: outside pin C's "seams under
`seeded-masks` alone"; gate it. `ProveError::Rerun` and `Kernel` still
carry formatted values (`node/prover/src/masked.rs:91, 118-121, 216`),
unlogged today [S]. Stwo's `info!(proof_size_estimate)` prints per
segment, leaf and fold at the default level, documented [S]; a `stwo=warn`
default filter removes it. `check-no-faults` is in `ci` only, with `-e
features` (dev edges) and the host target, unlike the umbrella.

### Info

- **Cross-venue windows.** The new venue trusts the founder-signed start,
  not the `Migrate`, so `[start, from_window)` may be anchored at both
  venues (honest nodes with one `S_w`), and nobody detects a cross-venue
  equivocation; by design (decision 8, "an anchor gives no integrity"),
  worth a line in pin D beside L3.
- **Duplicate keys in a genesis** pass the decode (numbers ascending, keys
  unchecked); the mock's count then differs from its map's. Refuse as
  `BadGenesis`.
- **The guest reads its storage leniently** (`state.rs:286-308`: an
  undecodable row is "absent"); its rows are its own, so defensive only;
  trap instead.
- **`migrate_digest` has no nonce** (`item.rs:93-95`); a refused migrate is
  valid again if control returns to its signer. Negligible.
- **Pin C's hedge** degrades to a function of the witness if OS randomness
  fails; `getrandom` failure is `ProveError::Entropy`, no fallback. Inherent,
  documented.
- **The 82.70 count** reproduced by hand: 26 + 24·(2.5 − log2 1.1) = 82.6999.

## The questions

**1. Soundness and zero knowledge of format 39.** 146 / 82.70 hold at the
tip and are pinned: `format_39_counts_146_and_82` asserts the parameter
tuple, the terms and 23 queries → 80.84; `the_masked_reference_shape_is_the_built_wraps`
derives the shape (B = 538, c = 3, the blinding, R and salts) from the built
components and asserts the count in [82.69, 82.70); the final verifier's
header and constants are tied to the registry [S, spot-checked]. Every mask,
salt, R column and blinding value comes from one ChaCha20 stream seeded by
pin C's hedge, the witness digest covering the statement words (the channel
tag included) and every main column; R1 runs on every attempt and fails
closed at 8; the preprocessed tree is circuit-only with its root pinned; the
composition's four columns, R's eight and the salts are committed before z
and the DEEP coefficients; the transcript matches pin B step for step in
prover and verifier; the verifier never calls Stwo's `verify` for 39 and
takes every pin from the format [S]. Nothing of the unmasked trace leaves
outside `watch`, which no production edge enables [V]. The 6.22 refactors
preserve behaviour as far as the guards show: fixtures and vectors are byte-
unchanged across `e21e25b0..bf895d27` but for G14's documented step [V];
the one gap is L1 (the seeded guard not run after the split; the diff shows
the draw order kept). The bump allocator is sound: live blocks never
overlap a reclaimed range, bounds are checked before every write,
`heap-peak` is gated [S]. The ZK and lifted-AIR algebra itself was not
re-derived here; it is the external audit's (decision 14).

**2. The on-chain protocol.** Registration binds the venue, the controller
and the signed start, bounded by the venue's time; the clock's length and
the key count are refused at refine; re-registration is `Again` [V].
Anchors: a listed key, `verify_strict` over the venue's digest, `Last < w <
now_w`, the age, the range; the same root `Again`, another root evidence
and suspension; `resume` only once no equivocator is listed; controls
nonce'd and venue-bound [V]. The hand-back path is sound: the leader takes
back only an anchor its own key signed over this venue's digest and, where
the cut root is kept, of the space's root over it; a `Window` behind a
later window settles and holds nothing back; two leaderships produce one
`S_w` from applied state [V]. Migration: `from ≤ w < until` on anchors and
`anchored` at every venue; the old venue serves `w < from_window` until it
ages [S]. `MaxRootAge`: one inclusive rule, ms, in five places that agree;
`Seen` pruned strictly after the newest root's expiry at every venue; no
deadline between parties uses a window number [V, S]. JAM: refine stateless,
roots non-empty only on code 0, accumulate accepting code 0 alone after
`anchored` and `seen`, the writes atomic under `FULL`'s trap, the prune
bounded at 2 an operand + 8 [V]. The mock shares `admit`/`judge` and
duplicates the anchor rule with code-naming differences only; H1, M6(a),
M6(c) and L7's folds are in the vectors [S]. **A wrong statement is not
accepted and a right one is not lost at either venue under honest keys.**
Under a compromised listed key: M1 (no evidence raised) and M2 (the
repudiated root reinstated).

**3. Privacy.** The audit is a sound regression gate for its needles in the
carriers it captures: the watched path is the production path, every random
draw of the wrap is noted and searched, the forms are planted and checked,
the `Recorded` reduction is justified now that every package is watched
before it goes and the service's storage is a `Leaves` carrier accounted
against the packages, and `carrier_except` skips by value in that carrier
alone [S, `carrier_except` and the `_forbidden` table read by me]. The
build gates cover every privacy-relevant feature (`watch`, `disclosing`,
`debug-internals`, `seeded-masks`, `test-formats`, `dump`, `heap-peak`, the
venue clients, the JAM crates), with `-e no-dev --target all`, each build
resolved once, a failing `cargo tree` failing the gate [V]. It is not yet
the proof of "nothing private leaves the prover" that `SECURITY.md` states:
the search floor (M6), the keys and unserved rows (M6), the live run's fault
text (M5), and what gets built (L3).

**4. The node.** Exactly-once holds in the narrow sense: by statement id,
the `proven` row first-only, the table synced on every write, `Proving`
re-queued and `Submitted` resubmitted at open, a `6` counted accepted, only
`leads()` submitting, transient codes retried to the anchor's age, `Unjudged`
bounded [S]. "Never dropped" and "bounded table" do not hold (M3, M4). The
layout version is right: written first and synced inside `open_tuned`, a
crash before it reopens empty and is stamped, the three refusals, no
migration and honestly so [S]. The stall bound is a safe Raft handover (no
campaign while stalled, `TimeoutNow` only to a caught-up target, three
failed handovers then step-down, commitment on the leader's durable index)
[S]; its cost to the worker is L6(e). The `vos` binary is clean for `-p
vos-cli` with and without `prover` and for `-p vos-node` [S: `cargo tree`];
a root workspace build is not (L3).

**5. Docs.** Accurate wherever they name code (constants, paths, features,
recipes, decision 17's reshaping) [S]. Stale where they carry numbers that
their own later sections correct (M7), lagging `SECURITY.md` against A.5
(M7), two carried limits not where their readers look (M7), the ELF's label
(M8), timelessness in the handoff doc and the model doc (L8).

**6. Carried items.** Complete and honest but for L7's omissions and item
68's unnamed owner call. Nothing carried must land before slice 7 on
soundness grounds: item 28 is host-input only; L3 and L4 are design limits
with no production producer yet; M6(d) is covered by §9.1's review clause
while no pallet exists; M5(d)'s release scan checks names that sit behind
`debug-internals`, never `debug_assertions`, so the debug scan is
equivalent; `SpaceGenesis::version`'s encoding is pinned byte for byte with
golden vectors. What must not wait is the decision on M2 and the design
statements of M1/M2/L3/L4.

## Must fix before close / may carry

**Must fix before close:**
1. M1: the clients send the node's anchor as evidence when the venue holds
   another root, and alert; a test through both clients.
2. M2: an owner decision, recorded in pin D, `spaces-pallet.md` §6 and
   `proving.md` §7, and a conformance vector pinning the post-resume
   behaviour (the code fix may carry if the decision is to keep the root).
3. The gate owed: the slice-gate tier green at `bf895d27` (`test-proof` at
   full N with the fixtures' byte-for-byte guard, `fuzz 300`), recorded.
4. Docs: M7 (A.6's numbers, the spike rows, `SECURITY.md`'s carrier table to
   A.5, L3 and L4 in the designs), M8's label, M6's floor stated, M5's
   carrier row, 6.18's failover claim qualified by M3, `SECURITY.md:421`
   qualified by M4(a), L7's list fixes and item 68 named.

**May carry (each a line in the plan's 6.22):**
M3, M4, M5's code, M6's needles, L1's `check` pin, L2, L3, L4, L5, L6,
L8, L9, the Info items.
