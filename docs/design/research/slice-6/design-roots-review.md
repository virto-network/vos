# Review: slice 6 design round — space identity, windows, roots, anchors, `&self` reads

Reviewer: Fable, 2026-10-18. Read-only, against `vos-core` at `31b7938e`:
`agent/tree/src/{lib,hash,build,update,store}.rs`, `agent/wire/src/{keys,apply,records,peer,result}.rs`,
`agent/wire/src/abi/cap.rs`, `agent/default/src/refine/{jam,invocation}.rs`,
`agent/default/src/refine/invocation/kernel.rs`, `agent/sdk/src/runtime.rs`,
`agent/sdk-macros/src/messages.rs`, `agent/test-actors/window/src/lib.rs`,
`pvm/proof/statement/src/lib.rs`; `docs/design/core-model.md` §7–9, §11–12;
`proving.md` §3.6, §6, §7, §11–12, A.5; `identity-and-authority.md` §11–14;
`slice-6-clerk.md` 5.2–5.4; `research/slice-5/kreivo-pallet.md` §2–5.

## Verdict

**Accept the shape; fix one blocker and nine majors before the first step is cut.**
The eight recommendations (SpaceId = genesis hash, Unix-time windows, X1 per-agent
cut, R4 keyspace, B1 representative with one node-key signature, S3 commitment
carry, F2 by ranges + convention, W1 no retention, a served channel) are the
right simplifications under the owner's constraints, and R4's central claim
checks out against the tree code. What is missing is mostly data flow and
protocol detail that the first milestone would hit on day one: the prover worker
cannot recover a `Statement` from the record as described; the served witness
has no transport into the step and breaks the work-result cap arithmetic as
sized; the representative's one-leaf-per-agent tree races with clock skew; and
the space root is built the expensive way when the machinery the design itself
introduces (a committed map cut at a window) already does the job.

Numbered findings follow, then the per-question answers, the "docs disagree"
calls, and the owner's decisions.

---

## Findings

### 1. [blocker] The worker cannot build the `Statement` from the `Attest` record as described

§6 says the worker "computes the statement id before proving" from "the decoded
`Served` header and `#[public]` prefix" of `witness_input`. `witness_input` is
the raw byte stream the kernel read (`kernel.rs:90`), `args ‖ served`. Which
bytes are the `#[public]` arguments is a property of the method's argument
types and attribute order, known to the macro, not to a node-side worker that
has only `ProgramHash` and bytes. Nor is `roots` recoverable without re-running
the prologue's verification natively. A venue needs `public_args`, `output` and
`roots` in the clear (`admit`, `statement/src/lib.rs:367-403`); the io-hash is
not enough.

**Fix.** Make the kernel's halt return the statement parts, and record them:
`Attest { program, window: Option<u64>, witness_input, output, public_args: Vec<u8>, roots: Vec<RootRead> }`,
written by the agent from what the kernel returns at halt (`runtime::attested`
already has all three in hand; extend `Output` or write them to a second
out-pointer the agent copies out). The worker then re-derives `io_hash` from
the record and checks it against φ9..12 of its traced re-run; a mismatch is a
bug, not a statement. This also gives `Statement` to the in-space side for
free.

### 2. [major] The served witness has no transport into the step, and the caps do not add up

§5.3 step 4: "the requesting agent's leader fetches `space_path`, assembles
`Served`, and proposes the resumption". The resumption is an *input* of a batch;
inputs are bounded by `REQUEST` = 64 KiB (`cap.rs:9`), and `Limits::served` is
256 KiB. The design says served bytes do not count against `attest`, but never
says what cap they do travel under. Separately, `ATTESTS × (REQUEST + REPLY + 40)`
is already a term of `STEP_RESULT` (`cap.rs:85`), asserted `+ 64 ≤ WORK_RESULT`
(`cap.rs:105`); 16 inline attests of 256 KiB each is exactly `WORK_RESULT`
(4 MiB) with nothing left for the rest of the result, so "inline is fine for
the first milestone" fails the existing `const` assert.

**Fix.** Decide the transport now: (a) a system input kind `Resume { request_id, served_hash }`
with `Served` fetched from the node's blob store by hash (slice 4's blob path
already carries work results this way), the record then holding the hash, not
the bytes (A.5's "the served part may move to a blob" becomes the first design,
not a later one); or (b) `Limits::served` sized so `ATTESTS × served` fits the
step-result budget (≈ 128 KiB with 16 attests, or 256 KiB with `attests` lowered
to 8 for `attest_at_cut`). (a) is the one that scales; the prover reads blobs
anyway. Either way the record's `witness_input` keeps A.5's 4 MiB as the
ceiling of the *kernel input*, not of the inline bytes.

### 3. [major] One leaf per agent in the representative races with clock skew

§3.2/§3.3: the agents tree has one leaf per agent, `kind ‖ A ‖ window_A`,
overwritten by each `AgentRoot`; the prologue requires `window_A == w`. An agent
whose leader's clock runs ahead of the representative's by more than `L − D`
sends `AgentRoot(w+1)` before the representative applies `Close(w)`; the
representative's log order is what counts, and its own batch time decides when
it closes. The leaf then shows `w+1` in `S_w`, and every statement of that
agent at `w` is refused by the prologue, though nothing lied. With `D = L/5`
the margin is 8 minutes at `L = 10 min`, a minute and a half at `L = 2 min`;
NTP outliers of minutes are routine.

**Fix.** Key the representative's rows `(agent_be ‖ w)` and have `Close(w)`
pick, per agent, the report with the largest `w' ≤ w` (keeping the two latest
windows per agent, pruning older). Equivalently, defer a report for `w' > w_now`
to its own row until `Close(w'−1)` has run. Both are a handful of rows per
agent. Also key by `kind` (finding 11).

### 4. [major] Build the space root with the machinery the design already introduces

§3.2 rebuilds the agents tree from scratch inside the representative's step at
every close (20k compressions at 10k agents, 12M gas on VOS through the
precompile; ~400M gas on JAM where there is no precompile, far past accumulate's
10M), and §5.3 has the representative "keep `space_path` per agent for `w`":
10k paths × ~0.45 KB ≈ 4.5 MB of output per window from one PVM step, against a
4 MiB work result. Neither is needed.

**Fix.** Let the representative's agents table be an ordinary
`CommittedMap<(AgentId, RootKind), (Root, Window)>`, written by the `AgentRoot`
handler. Give the representative the window clock offset by `D`
(`origin_rep = origin + D`), so *its* X1 cut at `B_w + D` *is* `Close(w)`:
`agents_root = A_rep(cut_rep(w))`, built by the node's root builder natively,
incrementally, and `S_w = H("vos/space/v1" ‖ space ‖ w ‖ A_rep)`. A `space_path`
is then an ordinary served proof against the representative's tree at its cut,
generated by the same builder pause as every other agent's `rows_proof`, only
for agents that asked (add `pending: bool` to `AgentRoot`). One mechanism, one
builder, zero hashing in the PVM, and §3.2's "no incremental structure needed"
becomes true because the structure already exists. The design's zero salt
becomes a seed-derived one (+16 B in the path); nothing to hide either way.

### 5. [major] The cut build's crash and leader-change ordering is unspecified

§5.4 W1 is right in outline (target `min(latest, next pending cut)`, `undo(w, key)`
rows for values accumulate overwrites before the cut build read them), but
three details decide whether a pending request survives a crash or a failover:

- **Proofs before resuming.** `rows_proof` must be generated and *persisted*
  (as local rows under `Owner::Tree`, keyed by request) in the same commit that
  marks the cut built, before the next batch rewrites tree rows. Otherwise a
  crash between "cut built" and "proofs generated" loses the window for that
  request. The design says "keeps it with the request" without saying when.
- **Every replica generates.** Only the leader proposes the resumption, but the
  leader may change between the cut and `Close(w)`. Either every replica's
  builder generates and persists the proofs (ms of work, deterministic bytes:
  `BatchProof::generate` over equal trees gives equal encodings), or a new
  leader whose builder has passed the cut must roll the request to `w+1`.
  Say which; recommend the former.
- **The `undo` write is on the apply path and needs a read.** `apply.rs:240-251`
  writes committed rows blind. To decide whether a key needs an `undo(w, key)`
  row, apply must read the current row (its version ≤ `cut(w)` and a build for
  `w` not yet complete), roughly doubling the committed write's 4.3 µs while a
  cut is pending. Fine at 20k writes/s, but the condition depends on *local*
  builder progress (`built`), so the `undo` row must be a node-local row
  written by the node's apply wrapper, never by the agent's deterministic
  `apply`, or replicas' states diverge. Several cuts can be pending when the
  builder lags across more than one boundary; `undo` must be per `(w, key)` as
  written, and the cut build for `w` must take `undo(w, ·)` over the row and
  skip dirty rows with version > `cut(w)` (the dirty key order, version first,
  makes that a scan bound; good).

**Fix.** Spell these three out in §5.4 and make them the acceptance tests of
step 3 (crash between cut and proof; leader change between cut and close;
two pending cuts).

### 6. [major] The `Cut` marker's time must be the leader's clock, never `B_w`

§2.3: "the leader appends a `Cut` marker when it has nothing else past `B_w`;
the marker moves the replicated batch-time mark past `B_w`". If a leader whose
clock trails `B_w` were to time the marker at `B_w`, it would push batch time
ahead of real time, which is exactly the fast-clock incident core model §8.4
treats as a liveness fault (sessions stop expiring, new ones refused). Read
literally the design is ambiguous.

**Fix.** The marker is an ordinary empty work result timed at the leader's
clock, appended once that clock passes `B_w` (so its time ≥ `B_w` by
construction). A trailing leader cuts late, never wrongly. And state the
inherited consequence: after a fast-clock jump of `Δ`, every window up to
`w(now + Δ)` is cut at once at one version, and the agent can make no *fresh*
statement until real time passes the mark. On JAM the marker and the
`AgentRoot` report are each a work package per agent per window, idle or not;
cheap on VOS, a fee on JAM (finding 15).

### 7. [major] F2 for rootless statements: enforce it in the pallet, not by audit

§4.5 picks "a convention in `public_args`, by audit" for rootless statements
whose effect must be single-venue. The venue is the one party that knows its
own id and sees `public_args` in the clear; the check is one prefix compare.

**Fix.** A per-program registry flag `venue_bound: bool`; when set, `submit`
requires `public_args[..32] == venue_id` before `judge`. The SDK then needs no
`vos/io/v2`, and the audit of a kernel is reduced to "does it put the venue
first", which the flag makes a build-time convention plus a chain-time check.
Keep (c) for rooted statements; the argument that a double anchor moves only
the space's own venue-local balances holds because every value-moving handler
is two-sided (finding 9).

### 8. [major] No protocol exists for changing `length_ms`; make it immutable in slice 6

§2.1: "a change of `length_ms` is a registry update that takes effect at a
stated future window". The cut is computed in every agent's deterministic
`apply` from the clock, so the new clock must reach every agent's *replicated
state* before the switch window, with the same `w_switch` everywhere: a message
from the representative to every agent, ordered against the boundary, plus the
venue's view of the same change. That is a protocol the design does not have.

**Fix.** `WindowClock` is fixed in the genesis for slice 6 (a space that wants
another length is a new space). The agent stores the clock at first install
beside `space` and `target`, from the genesis the node holds. Defer the change
protocol until a space asks for it.

### 9. [major] Say what an anchor is good for, and what it forces on the Clerk

§3.3 says it plainly: an anchor gives ordering and non-equivocation, not
integrity; a space can anchor any root of its own making. Two consequences are
not drawn:

- **Every value-moving handler must be two-sided** (A's "sent through s: X" and
  B's "credited through s: Y" both proven, netted only when they agree) or
  funded from the submitting space's own escrow. A one-sided "pay Z from the
  pool" is the space authorizing a payment from its own funds, which is fine;
  a one-sided "B owes A" is unenforceable. The pallet's handler contract should
  say so, and `Record` + `ClerkSettle` are the only handlers the design should
  admit until a third kind is argued.
- **Counterparties must anchor on the same venue.** The settle handler needs
  both spaces' anchors at *its* venue; with one anchor venue per space, a pair
  on Kreivo and JAM cannot settle until one migrates. State it in
  `slice-6-clerk.md` 5.2.

Credential statements to third parties ("balance ≥ Y") rest on the space's
honesty about itself; that is a product fact worth one sentence in §4.

### 10. [minor] R4 is correct; its migration list misses four items

The claim holds: the tree over a key set is unique (`lib.rs:36-49`), a branch's
level is the first differing bit of its keys (`build.rs:28`), so the smallest
subtree containing every `0x03`-prefixed key has level ≥ 8 and contains nothing
else; leaf hashes do not depend on depth, branch hashes commit level and
children only. The node at prefix `0x03` of JAM's whole tree equals the root of
the tree over those keys alone, byte for byte, and the map nodes at
`0x03 ‖ instance ‖ tag ‖ transform` likewise. Degenerate cases agree too (one
row: the leaf; none: `empty_root` on VOS, absence on JAM). Missing from §3.1's
cost list:

- `instance_prefix` / `owned_by` (`keys.rs:406,682`) define "everything an
  instance owns; its ABI reaches nothing else" and are used for ownership
  checks and prefix scans in tests and the store. Committed rows leaving
  `0x01 ‖ instance` means `owned_by` must accept `0x03 ‖ instance` too, or the
  ABI fails closed on its own maps.
- JAM's `commitment()` and the root-after writes (`jam.rs:166-172,220-228`)
  hash the stored bytes (`STORED ‖ version ‖ value`); VOS hashes the bare value
  (`roots/mod.rs:543-557`). The witness must keep carrying stored bytes (apply
  reads them through `unstored`/`unversioned`), and the leaf must hash the bare
  value for `0x03` keys only. R4 makes the class decidable from the first byte,
  which is a point in its favour; write it down.
- `is_committed`, `committed_entry`, `dirty`'s `map_key`, the testkit's `held`
  (`testkit/src/memory.rs:17`) and `base.rs:123` all key off `key[5] == Part::Committed`;
  dropping the `Part` byte changes every one.
- An `Ordered` key of 64 bytes with zero bytes escaped can take the leaf
  preimage (13 + 2 + key + 32) past one 128-byte block; today's "+10 B stays
  within one block" holds for hashed keys only. Cosmetic, but the counts in
  §5.5 assume one compression per leaf.

Per-map roots, the builder's incrementality and the Clerk are unhurt: one
`RootRow` per agent, one `Built` watermark, one sorted batch; a map's root is
its node, reachable in ≤ 80 bit-steps from the top, and `MapStore::new` already
takes an arbitrary `Child` as top for proofs against it.

### 11. [minor] Key the agents tree by `(agent, kind)` now

§3.2's leaf is one `kind ‖ root ‖ window` per agent, with Poseidon2 "a map
outside this tree, its own root kind in the agent leaf". An agent with both a
Blake2b tree and a Poseidon2 map (slice 7, the credential AIR) then needs two
leaves or a `v2` leaf. Keying by `agent_be ‖ kind` (5 bytes) costs nothing today
and removes a format bump mobile would otherwise force. Folds into finding 4's
map key.

### 12. [minor] `AnchorGrace` is unnamed; use `MaxRootAge`

A representative down across several boundaries closes the missed windows on
return (the design's X1 logic gives each the same leaves); the venue takes an
anchor only within `AnchorGrace`. Two constants where one does: accept any
`Last < w ≤ now_w` whose age is within `MaxRootAge` (24 h), since nothing
older is kept anyway. `w ≤ now_w` (not `< now_w`) lets a fast-clocked space
anchor during the venue's current window; harmless, the space's cut defines
the content.

### 13. [minor] The worker: who runs it, and what it skips

§6 says "a node extension"; if every replica runs it, a space proves each
statement `N` times and all but one are `Repeated`. Name the role: the leader
of the agent whose record it is, with the job table local and the venue's
`seen` as the only coordination (a failover re-proves at most the in-flight
statement). Also: a statement whose anchor will be older than `MaxRootAge`
before `t_prove` ends is dead; skip it and report it, rather than prove and be
refused `Unanchored`.

### 14. [minor] A read-set miss costs a window

§5.1 traps on a key outside the declared set, so a kernel bug costs the caller
one window of latency per retry. The host knows the read set before the cut;
let `attest_at_cut` fail fast at request time on malformed or duplicate keys,
and say that range reads (`RangeProof`, which JAM's witness already serves) are
out of scope for slice 6; the Clerk's aggregate rows need none.

### 15. [minor] JAM costs the design does not state

X1's marker and the `AgentRoot` report are two packages per agent per window on
JAM, idle or not; B1's pair messages are JAM transfers, which core model §12
says are unbuilt. Neither blocks slice 6 (Kreivo first), but §3.3's "the
representative is also JAM's representative service later" should carry the
dependency, and the JAM-side cut could lean on `timely`'s slot check instead
of a marker once it matters.

### 16. [minor] Milestone ordering: one spike before the keyspace change

M3.2a's order (types → R4 → cut → space root → `&self` → test actor → measure)
retires risks in cost order, not risk order. The largest unknown in M3 is the
in-kernel prologue: `verify_encoded` over `rows_proof` and `space_path`, the
public-args encoding and the io-hash, their steps and compressions against the
1M-step window target. That needs no R4, no cut and no representative: a
hand-assembled `Served` against today's map root and a fabricated agents tree,
run through a prototype prologue in the test harness, gives the numbers in a
day or two. Do it as step 0; it also fixes `Limits::served` from measurement
(finding 17) and decides finding 2's transport. Keep the Kreivo P0 pallet in
parallel from step 1 as the design says. Nit: define `cut(w)` as "the state
version before the first applied result with time ≥ `B_w`"; "version − 1" reads
either way.

### 17. [minor] `Limits::served` should be argued from compressions, not bytes

256 KiB of paths ≈ 7k compressions ≈ 4–5 min of proving by §5.5's own figures,
above JAM's 4,096 kernel cap, so on JAM it binds nothing and on VOS the real
bound is the method's `#[attestable(gas = N)]`. State the cap as the kernel's
declared gas on both hosts with `served` as the byte ceiling that gas implies
(or simply 128 KiB if finding 2(b) is taken).

---

## Answers to the eight questions

1. **Keyspace (R4).** Correct against vos-tree (finding 10): keys are full row
   keys, salts `salt(seed, full key)`, leaves hash the bare value on both hosts
   once JAM strips the versioned framing for `0x03` keys. Migrates: `keys.rs`
   (`Owner::Committed`, no `Part` byte, `owned_by`), the builder (one tree per
   agent), `jam.rs` leaf commitment, testkit, fixtures, the window kernel. Per-map
   roots survive as nodes; incrementality is unchanged; the Clerk is unaffected.
2. **Clock and cut (C3, X1).** Deterministic and replay-safe: the cut is a
   function of the log's batch times, `apply.result` refuses `time < latest`,
   the marker (timed at the leader's real clock, finding 6) finalizes it across
   leader changes. Skew moves the cut's wall time, never its content. A lagging
   replica reads the cut from its log; a lagging builder needs the `undo` rows
   (finding 5). No bad interaction with slice 3/4's skew rules provided the
   marker never synthesizes a time. Make the length immutable (finding 8).
3. **Space root and anchors (B1).** Honest equivocation is excluded by the
   representative's log; a down representative stalls anchors, not cuts; missed
   windows close on return within `MaxRootAge` (finding 12). The leaf-overwrite
   race is the real defect (finding 3). Ordering-not-integrity is enough for the
   Clerk because settlement is two-sided, and for credentials because the space
   vouches for itself; say both (finding 9). 24 h pruning is safe under S3 given
   `MaxRootAge > L + D + t_prove + backlog`; the worker should enforce it
   (finding 13). Prefer building the root from the representative's own
   committed map at its own cut (finding 4).
4. **Commitment carry (S3).** Sound: the venue's handler stores `c` per
   `(A, B, currency)`; a statement must open `c_prev` inside the kernel and
   match it outside, so a stale or forged carry is refused and the chain of
   `c` gives ordering. "No history" holds for trees and anchors; each space
   keeps its last settled marker row (bounded rows, not versions), and both
   sides must be able to state the same `s`, so marker rows are keyed by `s`
   with a small retention. Fine.
5. **F2.** Ranges suffice for rooted statements. For rootless ones the
   convention should be a per-program pallet flag with a prefix check
   (finding 7); no `vos/io/v2`.
6. **`&self` reads.** The declared read set, `attest_at_cut`, the capped
   builder and `undo` rows are the right design; finding 5 lists what makes
   them correct under crash and failover, finding 2 what carries the witness,
   finding 1 what the record must hold. Retention W1 is right: on-demand
   statements wait at most one window. Cost at scale: the cut costs the
   builder a pause and the apply path one read per committed write while a cut
   is pending; proofs are milliseconds. `Limits::served` per finding 17; the
   17-minute figure for 1 MiB is coherent with §11.2–11.3's numbers.
7. **Worker.** Idempotence by statement id is right once the id is computable
   (finding 1); name the role and skip dead statements (finding 13). The
   throughput rule `Σ t_prove ≤ P × L` is the right one; add the backlog report.
8. **Milestone.** Right items, one spike short (finding 16); fold findings 1–2
   into step 5's definition and finding 5 into step 3's tests.

## "Docs disagree, X wins": which I would reverse

None outright; the eight calls are right. Two I would qualify:

- **§8.3, C3 wins:** yes, with the length immutable in slice 6 (finding 8) and
  `AnchorGrace` folded into `MaxRootAge` (finding 12).
- **§8.5–8.6, "the code is right today" and "inline is fine for the first
  milestone":** the code is right, but the inline record fails the existing
  cap assert; go by hash from the first milestone (finding 2).

And one call the design makes implicitly that I would reverse: §3.2's "no
incremental structure needed in slice 6; rebuild from scratch each window".
The incremental structure exists already, and using it removes PVM-side hashing
and the per-agent path storage (finding 4).

## The owner's decisions, with recommendations

1. **`SpaceId` = hash of the genesis record (a).** Take it. No controller in the
   preimage; founding node keys sign registration; the controller signs
   migrations. Add `WindowClock` to the genesis and freeze it (finding 8).
2. **Clock C3, `L ∈ [2, 60] min`, default 10.** Take it. Note the Clerk's
   finality ≈ `L/2 + 5 min` and the fee of 144 anchors a day; 10 min is a fair
   middle. Keep `D = min(L/5, 2 min)`, or lengthen `D` if finding 3's fix is
   not taken.
3. **Agent root R4.** Take it; it is the only option that makes the kinds equal
   by construction with no extra hashing on either host. Budget the migration
   per finding 10.
4. **Builder and signer B1, one node-key signature.** Take B1, with the
   representative as a committed-map agent cut at `B_w + D` (finding 4) and
   rows keyed `(agent, kind, w)` (findings 3, 11). One signature is right under
   crash faults; register the representative's replicas' node keys as the
   anchor keys and rotate through the controller.
5. **Spans S3, `RootKind { Space }` only.** Take it. It retires `Carried`, the
   two-anchor read and the creation-window device, and bounds history to a
   marker row per pair. The Clerk's pair rows become cumulative aggregates
   (decision 4 of `slice-6-clerk.md`), which is the simpler Clerk anyway.
6. **F2: (c) plus (b).** Take (c); replace (b)'s audit with the pallet flag
   (finding 7).
7. **Retention W1.** Take it. W2 is a gigabyte a window at 1k writes/s and buys
   only statements at past windows, which nothing asks for.
8. **Served cap.** Serve by hash through the blob path and cap the kernel by its
   declared gas; 256 KiB as a byte ceiling is fine once it no longer sits
   inline (findings 2, 17).

Two decisions the design should add to the list:

9. **Venue co-location for the Clerk** (finding 9): counterparties settle at one
   venue; state it, and let the pallet's `ClerkSettle` be the only
   value-moving handler until a one-sided case is argued.
10. **The worker's role** (finding 13): the agent's leader, job table local,
    dedupe at the venue.
