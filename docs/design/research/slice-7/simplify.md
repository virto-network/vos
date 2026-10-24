# Simplifying the anchoring and venue protocol: a first pass

Research for slice 7's "simplify and scale" milestone (`slice-7-mobile.md`,
M3.9; owner decision S1(a)). It inventories slice 6's pin D as built, at
`f83f744b`, and lists the candidates for the owner to choose among. Nothing
here is decided. Tags: [measured] counted in the code; [est] estimated from
the counts; [proposed] a recommendation.

## 1. Why

Pin D grew in every review: the registration's signed start (plan 3's
blocker), the authorities map and the budget, the waits that a fee makes
expensive, rotation (6.14b), the hand-back, the honest node's evidence
(slice-end M1), the disputed window (decision 18), the cache that forgets
(F1). Each fix was right on its own. Together they make a state machine
that no one reviews whole:
- **about 110 enum variants on the anchor and submit outcomes alone,
  about 150 with registration, migration, control and status**, in 20
  enums across five layers (venue, venue client, queue, leader, worker),
  with `Again`, `Window` and `Key` each meaning different things in
  different enums [measured];
- **16 distinct wait, retry or settle paths for one anchor** on the node
  (node-side inventory, below), and two mechanisms each for recovering an
  unlanded anchor, for retrying `Open`, for not resending a refused key,
  and for detecting a suspension;
- **the same rule written many times:** the anchor rule at 3 venues (each
  in its own check order) and re-derived by 2 clients; the freshness
  formula `now − B_w ≤ MaxRootAge` at 8 sites; "is this root anchored" 7
  times; the range check 8 times; resume's "no equivocator listed" 3
  times [measured].

**Size of what is in scope** [measured, non-test / test lines]:
- the node side (the leader's cut, close, anchor and serve paths, the
  roots' cuts, anchor keys, the agent's closes and serving, the prover's
  job table, the queue): about 4,750 / 6,200;
- the venue side (`vos-venue` without the mock: 2,988; the Kreivo mock
  2,129; the conformance generator 3,208 test; the JAM statements service
  2,238 + 1,393; `vos-anchor` 887 + 454; `vos-statement`'s judge and model
  777 + 417; jam-dev's client 510 + 258): about 9,500 / 6,000.

## 2. What must survive any simplification

These carry the anchor's whole value (ordering and non-equivocation, pin
D) or a property a statement's soundness needs. No candidate touches them:
- **one root per `(space, w)` at a venue**, a second root stored as
  evidence that stops the space, and the honest node sending its own
  anchor as evidence when it sees another root held (slice-end M1);
- **the anchor's signature** by a key the venue lists for the space;
- **`Last < w < now_w` by the venue's time, and `MaxRootAge`**;
- **`Seen`** and its expiry for rooted statements;
- **the served path's checks in refine** (`serves`): the live answer a
  workflow acts on is as true as the replicated close;
- **time between parties is the venue's** (decision 2's rule).

## 3. The candidates

Each: what it removes, what it costs, its safety impact, and a
recommendation. Line counts are non-test unless marked [est from the
inventories].

### C1. One venue per space, no migration

- **Removes:** `Migrate` and its digest, `MigrateRefusal` (4),
  `MigrateCode` (8), the JAM `Migrate` item, Kreivo call 5, errors 24 and
  28, event 5, `end_window` / `Range.until` and its encoding, the
  `Migrating` harness, G14; the range check becomes a start bound at 8
  sites. About 250–300 lines and their tests [est]. **Pin D's known limit
  "equivocation is per venue across a migration" goes with it.**
- **Costs:** a space that must leave its venue (the venue dies, its fees
  rise, Kreivo to JAM) re-founds under a new genesis, so a new `SpaceId`:
  its counterparties re-link, and the Clerk's carried pair commitments
  restart. Today's rule already makes a departed space re-found to return.
  The Clerk has both counterparties at one venue anyway
  (`clerk-across-spaces.md` C.5).
- **Safety:** better: the one cross-venue overlap pin D could not detect
  disappears.
- **Recommendation [proposed]: take it.** A space that moves venues
  re-founds; a later slice adds migration back if a real space needs it,
  with the overlap problem solved then.

### C2. Anchor key = node key; no rotation beyond replacing a node

- **Removes:** `NodeRow::AnchorKey` rows, `rotate` and
  `vos node anchor-key rotate`, the newest-listed selection, the leader's
  `key_refused` memo and its `Key` branch, Kreivo's key-to-authority
  update semantics (an `add_authority` that swaps a paired key), most of
  `cluster/anchor_keys.rs` (807 test lines). About 250–350 node lines
  [est].
- **What stays:** the venue's list of anchor keys per space (founding keys
  at registration; the controller adds and removes keys). A node signs
  with its node key or not at all; a node whose key is not listed does not
  replicate the representative (the replica rule stays, simpler).
- **Costs:** a compromised or lost node key is answered by replacing the
  node (a new node with a new key, the controller listing it and delisting
  the old), not by rotating in place. A single-founder space that
  equivocates cannot rotate and resume (moot under C4).
- **Safety:** neutral: the response to a key compromise is the same
  (delist the key), with one fewer key per node to guard.
- **Recommendation [proposed]: take it.**

### C3. No hand-back: re-sign from replicated state only

Today an anchor whose key is delisted while queued is handed back by the
client (`Fate::Resign`, `VenueClient::unsettled`), held in front of the
space's later windows, re-signed by the leader with another key, and the
leader separately re-seeds waiting windows from its kept cut roots after a
leader change. `seed_waiting` already covers everything the hand-back does
while the representative's cut root is kept; the hand-back adds only
windows past `CUT_KEEP`.
- **Proposal:** the representative's close records `S_w` in a replicated
  row (`anchor(w) = S_w`, 40 bytes, kept for `MaxRootAge`: 144 rows at
  L = 10 min). One loop on its leader: for each `w ≤ close_mark` whose row
  the venue does not hold (the client's read of the venue's `Last` and the
  window's anchor), in window order, sign with the node key and send; on a
  batch, or every 2 s idle. The client's queue becomes a sender that
  resubmits the same bytes until the venue answers; a repeat is taken.
- **Removes:** `Fate::Resign`, `VenueClient::unsettled`, the queue's
  `unsettled`, `held_back`, `recheck`, `UNSETTLED_RECHECK`, `push` against
  `push_listed`, the replace-by-new-signer rule (about 110 of the queue's
  241 code lines); the leader's `signed`, `foreign`, `seeded` and
  `refused` bookkeeping, `take_up`'s hand-back loop and `reseed_wait`'s
  poll (about 150 of `anchor.rs`'s 411); the representative's exception of
  keeping 4 cut roots (back to 2, as every agent); finding L5 (jam-dev's
  `push` wedge) and the carried "recheck once a window length" test gap.
- **Costs:** none in capability under C2 (with one key a node, nothing
  needs re-signing by another key); 40 bytes a window replicated.
- **Safety:** better: the leader signs only what the replicated close
  holds, so the "foreign anchor" check becomes structural.
- **Recommendation [proposed]: take it** (with C2; without C2 it still
  works, re-signing with the newest listed key from the replicated row).

### C4. Equivocation is terminal

Today evidence suspends the space; the controller delists both signing
keys and calls `resume`; the disputed window stays dead (decision 18); a
single founder rotates first (6.14b).
- **Proposal:** evidence ends the space at that venue for good: no
  `resume`. Its roots are refused from then on, as a suspended space's
  are today, and the space re-founds under a new genesis to anchor again.
- **Removes:** `resume` at the three venues (and its three "no
  equivocator listed" checks), JAM's `equivocators` and `Op::Resume`,
  Kreivo call 6, error 23, event 9, `set_status`'s re-suspend branch, the
  evidence rows' lifecycle (finding F3 disappears: nothing reads them
  after), decision 18's disputed-window rule and G19, G5's resume half,
  the node's `Suspended` waits and alerts, the Kreivo client's F1
  cache-forgetting, the single-founder recovery. About 200 venue lines and
  150 node lines, and 300–400 test lines [est].
- **Costs:** an honest space whose key was stolen loses its `SpaceId` at
  that venue: statements in flight fail, counterparties re-link, the
  Clerk's pair commitments restart. An equivocation already means a
  stolen key or a byzantine node, which the trust model (crash faults
  only, core model §5) does not survive gracefully anyway.
- **Safety:** better: no path re-admits a space after a dispute, so no
  rule about which of its roots count is needed.
- **Recommendation [proposed]: take it.** Option kept for the owner: a
  governance-only revive at Kreivo (`StatusOrigin`), outside VOS's nodes.

### C5. Collapse the refusal and fate taxonomy

- **Proposal:** every venue client answers the leader with one enum,
  shared by all venues:
  - `Taken` (new, a repeat, or queued for sending);
  - `NotYet` (the window still open by the venue's clock, the space not
    yet registered, the venue paused): the leader waits and retries;
  - `Never` (the window at or behind `Last`, aged past `MaxRootAge`, a bad
    signature, an unlisted key): settled, with an alert carrying the raw
    code;
  - `Stopped` (the space suspended, blocked or ended by evidence): no more
    anchors until an operator acts; alert.
  The venue's own codes stay where they are pinned (`Refusal` 1–7 and the
  proof's `0x1xx` for statements, which the fixtures and vectors pin; the
  pallet's errors, which are the teammate's), each mapped in one table per
  client. The worker's submit outcomes collapse the same way: `Accepted`
  (a repeat included, at one site), `Refused(code)`, `Retry`.
- **Removes:** `AnchorRefusal` (8) and `Anchored` (3) → 4; `Fate` (4) →
  3; Kreivo's `Answer` (7) and its second mapping in `place`; the
  overloaded `Again`/`Window`/`Key`; the five "repeat means accepted"
  sites → 1; `Status` (4) → 3 [est: about 40 variants and 150–200 lines].
- **Costs:** less detail on the node's typed path; the logs keep the raw
  code.
- **Safety:** neutral, if each client's table is tested against every
  venue code (the conformance vectors drive the Kreivo one).
- **Recommendation [proposed]: take it**, after C2–C4, which remove most
  of the cases it collapses.

### C6. One anchor rule, written once

- **Proposal:** a pure, `no_std` venue core in `vos-anchor` (or beside
  `vos_statement::model`): `register`, `anchor`, `anchored`,
  `seen_expiry` and `fresh` as functions over a small state trait, used by
  `ModelVenue`, the JAM service's accumulate and the Kreivo mock, and
  vendored in the kit so the teammate's pallet may call it too. The
  clients stop re-deriving the rule from caches: they send, and map the
  venue's answer (C5).
- **Removes:** two of the three anchor rules and their divergent check
  orders, the 8 freshness sites, 6 of the 7 `anchored` implementations,
  the 8 range checks, `ModelVenue`'s two parallel stores, the Kreivo
  client's `anchor()`+`ready()` pre-checks and its `behind()` synchronous
  read on the batch thread (finding F2) [est: 400–600 lines].
- **Costs:** the pallet's design (`spaces-pallet.md` §6.1) is stated as
  "call the core", a change to the handed-over design; FRAME's storage
  stays the pallet's.
- **Safety:** better: one implementation for the reviewers, and every
  venue judges alike by construction, not only by vectors.
- **Recommendation [proposed]: take it.**

### C7. Fewer kinds of statement: rooted only at the venues

- **Proposal:** venues judge rooted statements alone in this slice: a
  statement naming `SpaceId::NONE` is refused (`Space`, 4). With C1 and
  rooted-only, `venue_bound` has no remaining job (a rooted statement is
  accepted only where its space's roots are anchored), so `Pin` returns to
  a program id.
- **Removes:** the rootless `Seen` rule (entries that never expire, and
  their storage cost at every venue), G9's rootless half, the space rule's
  rootless branch, `venue_bound` at six sites and in the governance delay
  rule, `Refusal::Venue` (7), the worker's rootless resubmission rule
  (finding L4 becomes "by design") [est: 150–250 lines; the fixtures
  regenerate].
- **Costs:** no venue verifies a rootless statement until a later slice
  brings a production prover and a handler for one (with `venue_bound`
  back then). Slice 7's device and credential proofs are verified at a
  space's ingress, not at a venue (`proving.md` §3), so nothing in this
  slice needs one. Every golden fixture is venue-bound today: they and the
  vectors regenerate (once, folded into the re-pin batch).
- **Safety:** neutral today (no production rootless prover); F2's venue
  binding for rootless statements returns with them.
- **Recommendation [proposed]: take it, if the owner agrees no rootless
  statement has a consumer before the Clerk.** Otherwise keep both kinds
  and `venue_bound` (they are small: about 20 lines for `venue_bound`).

### C8. Registration starts at the venue's next window

- **Proposal:** a registration anchors from `now_w + 1` by the venue's
  clock; the start is not an argument. The founder signs
  `(venue, space, controller)`.
- **Removes:** `start_window` from the digest and the call, its bound and
  `BadStartWindow`, plan 3's blocker class (a resubmitted start) by
  construction [est: 40–60 lines; G1 and G18 shrink].
- **Costs:** a space cannot back-date its first anchored window; the
  windows before registration are unanchored, which gaps already allow.
- **Safety:** better: no field left to replay.
- **Recommendation [proposed]: take it.** The known limit "one founding
  key registers the space anywhere under a controller of its choosing"
  stays carried (its lever, a controller co-signature or a founders'
  quorum, adds a rule; it is not a simplification).

### C9. No re-cuts: a read not closed in time fails, and the caller asks again

Today a read whose window has no `Closed` by the next cut is re-cut at the
next window, up to `RECUTS` = 2, so `READ_WINDOWS` = 3 and `CUT_KEEP` = 4.
- **Proposal:** a read is served at its own window or fails
  `NotClosed` at `B_{w+2}`; the SDK's `attest_at_cut` re-asks once at the
  next window when the caller opts in.
- **Removes:** `moved(w)` and `serving` rows, `RECUTS`, the chain walk
  (`serving_windows`) on the node and in refine, `served_at`'s moved
  reads; `CUT_KEEP` falls from 4 to 2 and `READ_WINDOWS` from 3 to 2 [est:
  150–250 lines, and about 500 test lines].
- **Costs:** a read fails instead of waiting when the representative
  misses a close or an agent's leader leads its clock by more than L − D
  (8 minutes at L = 10): both faults an operator must fix anyway. A
  representative outage across a close fails that window's reads.
- **Safety:** neutral (liveness only; the served path's checks stay).
- **Recommendation [proposed]: take it**, measured in the scale test with
  real clocks: the fail rate of reads at the real skew of the owner's LAN.

### C10. Agents report, and cut, only when a read waits

Today every agent of a space reports its root every window: a marker, a
build, a Raft entry and a pair message at the agent, a Raft entry and a
committed write at the representative. That is linear in agents (about 50
s a window at a million agents, the 6.19 ops note), and `RepKey(agent, 0,
w)` has no consumer but a read's path.
- **Proposal:** an agent appends a marker, builds a cut and reports only
  for windows in which a read of it waits; a report then means "a read
  waits" (the `pending` flag and the `asked` table merge into it).
- **Removes:** the `asked` table and its pruning, the `pending` flag, the
  idle agents' markers, builds and reports; `S_w` covers the agents that
  read in w.
- **Costs:** `S_w` no longer commits to every agent's root at w; no
  consumer reads those rows.
- **Safety:** neutral.
- **Recommendation [proposed]: take it**; it is the representative's
  scale lever, built in 7.3 and measured by the scale test (7.6).

### Considered and not recommended

- **Dropping the representative's close delay `D`:** it is what lets
  late reports miss a window rather than race it; without it, cut and
  close merge and every skew becomes a race.
- **Dropping `Last < w` ordering (allowing out-of-order anchors):** the
  in-order send is what makes a window behind `Last` final; out of order,
  every client needs a per-window record of what landed.
- **Dropping the honest node's evidence submission:** without it a stolen
  listed key that anchors first is never caught (slice-end M1).
- **Kreivo-only governance** (pause, blocked, budget, deposits, sovereign
  dispatch, fees): the teammate's pallet; it stays out of the node's
  state machine under C5.

## 4. What the protocol looks like with C1–C10

- **Registration:** a founding key signs `(venue, space, controller)`;
  the space anchors from the venue's next window; its founding keys are
  its anchor keys; the controller adds and removes keys.
- **Anchoring:** the representative's close records `S_w`; its leader
  signs pending rows in window order with its node key and sends; the
  venue answers `Taken`, `NotYet`, `Never` or `Stopped`; the rule is one
  function every venue calls.
- **Equivocation:** evidence ends the space at the venue; an honest node
  sends its own anchor as evidence; the space re-founds.
- **Statements:** rooted, at an anchored window, at the one venue.
- **Reads:** served at their own window, or `NotClosed`; only reading
  agents report.

**What goes, in all** [est]: on the node about 1,000–1,400 of 4,750
lines, the leader's anchoring state from nine fields to two, the anchor's
wait paths from 16 to 4; on the venue side about 1,200–1,600 of 9,500
lines (the generated vectors shrink: G14 and G19 go, G1, G5, G15 and G18
shrink); about 2,500–3,500 test lines; about 70 of the 150 outcome
variants.

## 5. What each choice touches outside VOS

- **The Kreivo teammate:** C1, C4, C6, C7 and C8 change
  `spaces-pallet.md` (calls 5 and 6, `start_window`, the anchor rule as
  the core's call, `venue_bound`, the rootless `Seen` rule) and regenerate
  the conformance vectors. If the teammate has started, each is a change
  to work in progress: the owner asks first (open question 2 in the plan).
- **The JAM statements service:** its blob changes (no blob hash is
  pinned yet; slice 6's L2 pins them with the re-pin batch, after this
  milestone).
- **The fixtures:** C7 regenerates them (every fixture is venue-bound
  today), folded into M4's re-pin batch.
- **The Clerk** (`clerk-across-spaces.md`): no conflict. It needs rooted
  statements at one venue for both counterparties, and tolerates gaps;
  C4 makes a counterparty's re-founding the response to its equivocation.

## 6. Order, if all are taken

C6 first (the core every later change edits once), then C1, C4, C8 and
C7 (removals at the venues, the vectors regenerated once), then C2, C3
and C5 (the node's anchoring), then C9 and C10 (the agent's reads and
reports). The plan's 7.1–7.3 follow this order.
