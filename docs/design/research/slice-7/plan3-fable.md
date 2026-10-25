# Review: slice 7 plan, draft 3 (`s7/plan` @ 9ef226a5)

Read-only review before implementation. Plan = `docs/design/slice-7-mobile.md`
(section refs below); research = `research/slice-7/*`; context = `proving.md`
§3–§8, `recursion-air.md` §1.3 and §5, `identity-and-authority.md` §5–§8 and
§11, `spaces-pallet.md` §5–§7, §9 and §13, `clerk-across-spaces.md` C.5,
`slice-6-on-chain.md` pins A–F and 6.22, `slice-6-progress.md` ("Slice 6
accepted"), and the code the plan cites (`node/host/src/leader/{anchor,
close}.rs`, `node/host/src/roots/cuts.rs`, `node/host/src/anchor_keys.rs`,
`node/venue/src/{lib,queue}.rs`, `node/venue/src/kreivo/venue.rs`,
`node/host/src/ingress.rs`, `agent/wire/src/{defaults,abi/cap,peer}.rs`,
`pvm/proof/src/{core/ecall,pcs,format,security}.rs`,
`pvm/proof/recair-air/src/masked.rs`, `support/vos-raft/src/core/election.rs`,
the statements service's `accumulate.rs`, and the Stwo fork at `c3ec981`).
The owner's decisions S1–S31 are taken as settled; where one is unsafe as
written or contradicts a pin, it is named under "Decisions to revisit".

## Verified

- Pin D′'s claim that honest leaders agree on `S_w` holds in the code as
  built: `closes()` reads the representative's closing root from the
  replica's *applied* state (`roots::closing_of`, `cuts.rs`: "the same
  bytes on every replica"), batch time is floored by the replicated
  `batch_time` row across leaders (`leader/batch.rs:54`), and the cut's
  version is fixed by committed log order. C3 formalises this as a row.
- `vos-raft` has `transfer_leadership(to)` (`core/election.rs:333`), so C5's
  `Unlisted` handoff has a primitive; the node host does not call it yet.
- The fork has `Blake2sM31Channel` and `Blake2sM31MerkleChannel`
  (`channel/mod.rs:14`, `vcs/blake2_merkle.rs:43`); `pcs.rs` names
  `ChannelKind::Blake2sM31` but decodes nothing for it, as "Not built" says.
- `MaskedComponents` (`recair-air/src/masked.rs:117`) is generic over the
  component set and channel; 7.10 and 7.14 both extend it.
- Device-format counts: `device-params.md`'s table is consistent with
  `security.rs` (`variant_c`, `DeepBatching::{Powers, Affine}`); the
  revealed-rows formula `4|O| + q(|O|+1)` gives h = 512 at 43 and 47
  queries (2^11 floor) and h = 1,024 at 86 (2^12).
- `AgentId` is a bare `u32` from `agent_id(creator, serial)`
  (`peer.rs:164`): not space-unique. This matters for H1.
- `cap::REQUEST` is 64 KiB and the ingress body limit is `REQUEST + 4 KiB`
  (`ingress.rs`); this matters for M5.
- The M5 outlook's arithmetic reproduces: 2.2 × 0.64 × (2.0–2.9) × 0.8 ×
  0.9 × (0.55–0.7) × (0.65–0.75) × (0.88–0.92) = 0.64–1.42 s.
- The critical path sums to 24.5–35.5 weeks (plus 4–6 for 7.19), as stated.

## Verdict

**Ready after fixes.** No redraft. Pin D′ is sound and simpler; its
remaining hazard is operational, not protocol (M1). M4 has one real
soundness-of-privacy gap (H1) and one revocation gap (H2), both one-line
fixes to pins I and G. M5's outlook is honest; its second re-pin (S23) has
its gate in the wrong place (H3). The schedule has one code collision the
plan does not name (M4). H1–H3 and M1–M5 go into the plan text before 7.1,
7.7 and 7.14 start; the rest can land in the steps' briefs.

## High

### H1. Pin I's scope is not namespaced by the space; with S25 that yields cross-space nullifiers

- **Where:** pin I "The scope"; pin K "The derivation"; S25.
- **Scenario:** `s` derives from `(handle, PRF output)`; the `SpaceId` is
  not in it (S25, by design). Space B's founder sets B's handle to space
  A's (the handle is public: pin G serves it with `path`). A member of
  both now has `s_A = s_B`, so `member(s, epoch)` and `owner(s)` are the
  same digests in both trees and ledgers. The scope is
  `P2(TAG_SCOPE ‖ H(agent ‖ instance ‖ name))`; agent ids are node-serial
  `u32`s, instance 0 and guard names like `"login"` repeat, so B's agent 3
  "login" has A's agent 3 "login"'s scope, and the member's nullifier is
  identical in both spaces: a pseudonym linkable across spaces, the
  "global handle" `identity-and-authority.md` §7 refuses. Even without a
  scope collision, B's operators link their anonymous members to A's by
  digest equality.
- **Fix:** `scope = P2(TAG_SCOPE ‖ BLAKE2b-256(space ‖ agent ‖ instance ‖
  name))`, the `SpaceId` first (ingress knows it). State in `SECURITY.md`
  that two spaces sharing a handle share their members' `member`/`owner`
  digests, and that the handle is therefore a founder-chosen value the app
  should display and pin at first enrollment. Test: two spaces, one
  handle, one secret: distinct nullifiers for the same guard name.
- **Also** (see "Decisions to revisit", S25): as written the stable handle
  buys little, since pin D′ still has members "register their leaves
  again"; its real benefit is that the operator can re-seed the new
  actor's tree from the ended space's `member` digests with no member
  action. Make that the re-founding runbook's step and S25 earns its cost.

### H2. The credential actor's root ring is bounded by count, not time: revocation does not take effect

- **Where:** pin G "Roots" (a ring of the last 64 roots, one per batch
  that changed the tree); pin I "Ingress checks" (`map_root` in the ring).
- **Scenario:** a space with 500 members enrolls or revokes a few times a
  month. A member is revoked (leaf removed, new root). The 63 earlier
  roots stay in the ring for months. The revoked member fetched a path
  under an old root before revocation (or simply keeps one) and proves
  `Auth` against it; ingress finds the root in the ring and accepts. The
  plan's "a new passkey or a revocation bumps the epoch" does not help: the
  old leaf is under the old root.
- **Fix:** the ring already stores `(root, batch_time)`. Ingress accepts
  the *current* root at any age, and an older ring root only if its
  `batch_time` is within `ROOT_MAX_AGE` (propose 10 minutes, covering the
  replica's lag plus `expires_ms`'s 120 s) of the replica's latest applied
  batch time; otherwise a retryable refusal (the client fetches a fresh
  path). The ring's count then only bounds storage. Test in 7.11: a
  revoked member's proof against the pre-revocation root refused once
  `ROOT_MAX_AGE` has passed by batch time.

### H3. S23's second re-pin sits on the recursion's 9.5% headroom, and its count is scheduled after the code is built

- **Where:** M5's outlook "One chip set, two formats"; 7.18; 7.21 "The
  recursion rechecked first"; `recursion-air.md` §5.
- **Scenario:** a kernel leaf's `p2` rows grow with the inner proof's
  *width × queries*, not its cells (`recursion-air.md` §5: 59,300 of 65,536
  at 8,009 columns and 40 queries; about 760 columns to spare). The CPU
  split by opcode family shrinks *cells* (each row pays its family alone)
  but *widens* the shape: every family component repeats the pc, the
  instruction word, the register indices, the timestamp and its selectors,
  and the Poseidon2 chip adds about 300 columns to any kernel that calls
  it. A 4-family split plus the chip plausibly adds 500–900 columns: at or
  past the headroom. The fallback the plan names, `p2` at 2^17, costs +70%
  on every leaf and fold and a new fold shape and `H_FOLD`; the window
  statement's 46.5 s gate would then regress far past 10%. 7.21 counts
  "before any code", but 7.18 has by then spent 6–10 weeks building the
  split for both formats.
- **Fix:** move the count to 7.18's first day (a day's work with
  `count-35`'s method over the proposed family layout, before the design
  is fixed), with an explicit exit written into the plan: if the kernel
  leaf exceeds 2^16 at 40 queries after the shape per kernel, the split
  enters format 41 only on the owner's fresh call (the fold change
  accepted, with its cost measured), else it stays device-only while the
  Poseidon2 chip alone enters 41 (the chip is used only by kernels that
  call `0x402`, so it widens only those). Keep 7.21's gates as written.

## Medium

### M1. Under terminal C4, a self-inflicted equivocation kills the space; the plan should guard the evidence path

- **Where:** pin D′ "Equivocation ends the space"; 7.2's tests; S11.
- **Scenario:** two honest leaders of one representative sign different
  roots for `w` only if their *applied* state diverged: an
  apply-nondeterminism bug (slice 6's reviews found two in the roots
  path), a node restored from a backup with a forked log, or an operator
  running two processes from one cloned store. Today that is a suspension
  the controller lifts; under C4 the honest node sends its own anchor as
  evidence and the space is dead, its re-founding a multi-day operation.
- **Fix, three parts, all small:**
  1. Pin D′ states that `anchor(w)` is written by apply and the leader
     signs only an applied row, never a root from the batch under
     proposal (the code already does this; write it down and test it: a
     deposed leader with an uncommitted close and a successor whose clock
     lags, both anchoring the same root).
  2. A divergence guard on the evidence branch only: before sending an
     anchor the venue would store as evidence, the leader asks its
     followers for their applied `anchor(w)`; if any differs from its
     own, it sends nothing and alerts "divergent replicas" (a local bug or
     clone, not theft). One peer round trip on a path taken only under
     attack or fault. If all agree, the evidence goes, as decided.
  3. `docs/operations.md`: a restored backup or a cloned store is treated
     as a compromised node key; the node is replaced before the space
     re-founds (else the re-founded space inherits the fault).

### M2. C5's `Unlisted` handoff is under-specified, and Kreivo cannot report `Unlisted` without a state read

- **Where:** pin D′ "The node's outcome enum"; 7.2; `simplify.md` C5, C6.
- **Scenarios:** (a) the controller delists every replica's key by
  mistake: each new leader is `Unlisted`, hands off, the next is
  `Unlisted`: an election loop that also stalls closes and reports.
  (b) The venue's listing as the client last read it lags one block
  behind an `add_authority`: a needless handoff. (c) On Kreivo a delisted
  authority is no longer in `Authorities`, so `ChargeSpaceFee` makes it pay
  its own fee from a zero-balance account: the pool answers
  `InvalidTransaction::Payment`, the same answer as "budget exhausted"
  (`spaces-pallet.md` §7). The client cannot map it to `Unlisted` without
  reading `AnchorKeys` or `Authorities[self]`, which C6's "the clients stop
  re-deriving the rule from caches" removes.
- **Fix:** pin D′ names the target (a replica whose node key the client's
  last listing holds), a damper (one handoff per window per leadership;
  when no replica is listed, alert and wait, no handoff), and the three
  state reads a client keeps that are not anchor-rule re-derivations: the
  space's record (`start_window`, status), `AnchorKeys` (for `Unlisted`
  and the handoff target), and `Last`/`Anchors[w]` (for "the venue does
  not hold w", which the C3 loop needs). All three are read on the
  client's own thread and consulted from a cache on the batch thread,
  which is slice 6's F2 done right.

### M3. The ingress verifier's denial-of-service exposure: the cheap checks do not filter an adversary

- **Where:** pin I "Ingress checks" and "Load"; 7.11; the risk table.
- **Scenario:** the scope, binding, root and expiry checks all pass for an
  attacker who computes them himself (the root is public: anyone asking a
  path gets it). The only costly gate is the proof at about 10 ms a core.
  With `ingress_connections` (1,024) bounded and an executor budget, the
  attacker still buys the whole budget for the cost of connections, and
  honest callers see `503`.
- **Fix:** (a) the verifier checks the PoW nonce before any Merkle
  decommitment; the transcript order (commitments, OODS, FRI commitments,
  PoW, then queries) allows it, so a garbage proof costs the verifier a
  few hashes while costing the attacker 2^20 hashes an attempt (about
  30–100 ms of his CPU for 10 ms of ours only if the PoW passes); gate:
  "a proof with a wrong PoW is refused in under 1 ms". (b) Fuzz targets
  for the `Credentialed` request's decode and the format 42/43 verifier
  (panic-freedom at ingress), as 6.7 did for the final verifier. (c) Keep
  the connection bound and executor budget as written.

### M4. Steps that run in parallel collide: 7.8 against 7.14, 7.10 against 7.14, and 7.11 against `blobs.lock`

- **Where:** "How every step runs"; 7.8; 7.10; 7.11; 7.14; "Estimates".
  The plan names 7.3 against 7.9 (resolved by pin G) but not these.
- **Scenario:** 7.14 (4–6 weeks, from day one by S7) edits each chip's
  finalize, the per-component `h`, the fixed tables' padding and the
  shared prover. 7.8 (after 7.3, weeks 5–8) lands slice 6's quality items
  13, 14, 18, 19, 21–26, 34 and 35 in the same files: `shape::chip` as one
  table, `chips_of_mask`, the CPU `Lookups` struct, the Blake2b column
  macro, `MIN_LOG_SIZE` and the max-log-size constant, the splits of
  `derive::kernel` and `DeepPlan::new`. Whichever lands second rebases
  weeks of work across renamed columns and moved functions. 7.10 and 7.14
  both extend `recair-air/src/masked.rs`. 7.11 changes the origin ABI and
  the session-less input kind in the agent image; if `blobs.lock` (L2, in
  7.8) covers the agent image, 7.11 re-pins it a second time.
- **Fix:** split 7.8 into 7.8a (the pvm-internal items, right after 7.0,
  before 7.14 touches a chip; it re-pins program ids and fixtures once)
  and 7.8b (the agent image, `SpaceGenesis::version`, `final-verify.elf`'s
  `ANCHORS` mode, `read_nat`, `blobs.lock`, after 7.3 and after 7.11's ABI
  change). Goal 5's "two re-pins" becomes "two program-id re-pins (7.8a,
  7.21) and one blob lock (7.8b)". 7.10's `MaskedComponents` extensions
  land before 7.14 consumes them (7.10 starts at week 2 anyway). State in
  7.11 whether its ABI change alters any pinned blob or fixture.

### M5. Pin I's 512 KiB cap refuses pin J's 1.5 MiB device proofs, and both exceed today's ingress body cap

- **Where:** pin I "Ingress checks, in order: the size (≤ 512 KiB); the
  format (42, or 43 for a device proof)"; pin J "the proof at most
  1.5 MiB"; `ingress.rs` (`cap::REQUEST + ENVELOPE` = 68 KiB).
- **Scenario:** a format 43 proof at blowup 2 and 86 queries over about
  2,000 columns is about 1.3 MB (`device-params.md` finding 6); the first
  check refuses it. Any credentialed request past 68 KiB is refused by the
  HTTP layer before the checks run.
- **Fix:** a per-format cap on the `Credentialed` route alone (42: 512 KiB;
  43: 1.5 MiB), the HTTP limit raised for that route only; the log entry
  carries the call and origin, never the proof, so `cap::REQUEST` and the
  Raft entry are unchanged. Add to 7.11's tests.

### M6. The scale test can mislead on uneven LAN hardware, and T2's extrapolation needs a stated assumption

- **Where:** 7.4 `check`; 7.6 runs 2 and 3; "The scale test" T2.
- **What misleads:** (a) a Raft group commits when the median replica
  fsyncs, so the slowest host gates every group it *follows*, not only
  those it leads: placement weights do not remove it from the knee;
  (b) a 1 GbE NIC: at 40,000 calls a second with 3 replicas the busiest
  host carries about 80 MB/s of replication plus answers, near the link;
  the knee may be a NIC knee; (c) laptop CPU governors and thermal limits;
  (d) a HDD or SATA data disk on one host; (e) the desktop running two
  nodes, the coordinator and `collect`; (f) a Wi-Fi host.
- **Fix:** `check` records link speed, `scaling_governor`, disk type and
  refuses Wi-Fi; `report` names the binding resource per host at the knee
  (CPU%, iowait, NIC utilisation against link speed); run 2 once more
  with the slowest host excluded and the difference reported; drivers and
  the coordinator never share a node host during a timed run. T2 states
  that "room for 8 million users" assumes `K` scales with users (65,536
  sessions an agent: 8 million users need `K ≥ 128`), since the agent is
  the unit of scaling.

### M7. The epoch in `member(s, epoch)` is state the device cannot keep and the actor cannot check

- **Where:** pin K "What a space stores"; pin I "Auth"; 7.13 "storing
  anything but the credential id".
- **Scenario:** after a reinstall the app holds the credential id alone;
  it does not know its epoch, so it cannot compute its leaf; the actor
  cannot verify the epoch a member claims (the leaf is a digest). In-space
  revocation is leaf removal (H2's fix makes it effective), and a new
  passkey yields a new `s` and so a new leaf without any epoch. The epoch
  exists in `identity-and-authority.md` §7 for cross-space credentials,
  which this slice does not build.
- **Fix:** drop the epoch from the leaf for this slice
  (`member = P2(TAG_MEMBER ‖ s)`): one fewer private input, one fewer
  device state, one fewer thing the demo gets wrong; or keep it and add
  `epoch(key)` to the actor's queries with its justification.

### M8. The device program id pins log sizes, so the kernel's trace length must be witness-independent

- **Where:** pin J "The device program id"; 7.15; leakage gate 7.
- **Scenario:** a Merkle-path kernel whose step count varies with the
  direction bits produces a trace of another log size for another
  witness; its proof names another program id and is refused, and the
  proof's shape leaks the witness (the gate 6.6 calls leakage 7).
- **Fix:** pin J states that the prover pads every chip to the program
  id's log sizes and fails on a run that exceeds them; the auth kernel is
  written branch-free (the path walked with selects); a test proves two
  witnesses of different path shapes under one program id.

### M9. Format 41 keeps "35's parameters" on a wider AIR without a recount

- **Where:** pin H "Format 41"; 7.21.
- **Scenario:** the batching, ALI and DEEP terms depend on sampled values
  and constraints; 35's 62.86 was counted on its own reference shape. The
  chip and the split add hundreds of sampled values; 41 may count under
  62 at 40 queries and PoW 24.
- **Fix:** 7.21 recounts 41 on its reference shape with the tool (one
  line) and pins it; queries or PoW move if needed, as 7.17's lever 4
  already does for 43.

### M10. The owner's phone is on the critical path about twelve times

- **Where:** "Phone gates"; 7.0a, 7.12, 7.13, 7.16, 7.17 (each lever
  "measured on the phone before the next", four times), 7.18 (PG2 twice,
  a day apart), 7.20, 7.23.
- **Scenario:** 7.17's four levers serialise on the owner's availability;
  a week's delay each is a month on the critical path.
- **Fix:** a second, permanently attached ARM device for the iterative
  measurements (any Cortex-A7xx phone), the Fairphone 6 for the gates
  alone; between sessions the x86 proxy with the measured 3.5× factor.
  The plan should budget the owner's sessions explicitly.

## Low

- **L1. The ended space's `RegistrationDeposit` is stranded** (pin D′;
  `spaces-pallet.md` §6.2 "released only by a later deregistration, not in
  this version"). Release the hold on `Ended`, or state that it is
  forfeited; `dispatch_as_sovereign` with `transfer_keep_alive` also leaves
  the existential deposit behind.
- **L2. `path(key)` and the handle's query are unauthenticated as written**
  (pin G). Say whether any caller or a member's session may ask, and what
  `key` is (the `member` digest, or an identity).
- **L3. The outlook omits the grind** (M5's outlook; `device-params.md`
  finding 5): PoW 20 is about 0.1 s median and 0.3 s at the 95th
  percentile on the phone, a tenth of the gate. Add it as a row; S29's
  PoW 16 lever applies to 43 too (7.16's candidates already carry it).
- **L4. The challenge route is not needed** (7.11): a client nonce,
  `expires_ms` and the recorded digest give exactly-once; the clock-skew
  problem is solved by the node answering its time on an existing `GET`.
  Cut it.
- **L5. `Stopped`'s doc says "suspended"** (pin D′); no `Suspended` exists
  under C4. Name the pallet's new `SpaceStatus::Ended` index (3; 1 retired,
  never reused) in `teammate-note.md`.
- **L6. The enrollment must bind the digests** (7.13 *Enroll*): the
  operator-granted invitation names the `member` and `owner` digests it
  admits, else an interceptor enrolls his own.
- **L7. 7.1 and 7.3 are tight.** 7.1 touches eight code sites, regenerates
  3,208 lines of conformance generator and rewrites `spaces-pallet.md` v2:
  3–4 weeks. 7.3 carries C9–C11 and six worker edges: 2–3 weeks.
- **L8. T4's C9 fail rate should be a reported metric**, not only a gate:
  the scale runs are the one chance to measure it at real skew.
- **L9. The per-call identity read is the hot path the test does not
  model** (7.5 "Not modeled"). Carry it by name in the table so the next
  scale run has it.
- **L10. 7.0b should also check the PRF across a reboot and a GPM
  re-sync**, since a changed `o` means a lost `s`; one more assertion, no
  more code.
- **L11. 7.0a's proxy omits the Blake2s-M31 Merkle hashing of the doubled
  leaf layer**, which dominated the wrap's factor (`proving.md` §5); it
  commits at n+1 but hashes the same tree shape. Say so, and read the
  proxy as a floor on the masking factor, not an estimate.

## Judgements, by the brief's eight questions

1. **Pin D′.** Sound: no path accepts a wrong statement (the served path's
   checks, `Seen`, `Last < w < now_w` and `MaxRootAge` all stay), and no
   honest fault stalls a space for good (every wait ends at `MaxRootAge` as
   a gap, which every venue allows). The false-positive question reduces
   to divergent applied state (M1); the honest nodes' agreement on `S_w`
   is structural once C3 is stated as "sign from applied rows". The
   `Unlisted` handoff needs its target and damper (M2). Re-founding is
   complete with the tombstone, the sovereign drain (L1) and the handle,
   provided the runbook re-seeds the tree (H1's note). It does come out
   simpler: the venue's statuses fall to `Active | Ended` (plus Kreivo's
   governance states), the node's outcomes to 5 and 3, the leader's
   anchoring state to what the replicated row implies, and the wait paths
   to four; the one new coupling is the handoff into Raft.
2. **M4.** The auth and pay statements are sound and zero-knowledge as
   stated once the scope carries the space (H1) and the root is
   time-bounded (H2): the binding names space, agent, instance, method,
   program, kind, arguments, nonce and expiry, so a proof authorises one
   call; the digest recorded at apply by batch time makes replay fail at
   every node. The PRF derivation is fine (248 bits, bias 2^-33); the
   containment is honestly stated. The verifier at ingress needs the PoW
   checked first and fuzzing (M3) and a per-format cap (M5). The tree in
   the actor's rows through `0x402` is the right simplification; its
   `path` query needs an access rule (L2). Drop the epoch (M7).
3. **M5 and 7.21.** The path to 1 s is honest: the plan says it reaches
   1 s only at the favourable end and flags the gate at risk. The counts
   for 42 and 43 are right on their masked shapes; 41's must be redone
   (M9). Shared chips are sound for both shapes given the per-shape
   forgery gates named; the leaf-overflow fallback is correctly listed but
   its gate is late and its cost understated (H3). Node proving will
   regress if the fold shape changes; the 46.5 s gate catches it, but only
   after the work is spent.
4. **The scale test.** T1–T6 measure the ledger path, the window pipeline
   and the per-replica cost, which is what "millions of users" needs from
   the node; the identity path is the honest gap (L9). On uneven hardware
   the knee is the median replica's and possibly the NIC's (M6).
5. **The Android demo and the phone gates.** Feasible as scoped; 7.0b is
   the right probe and its fallbacks are correct. The PRF handling's
   weakness is the handle, not the derivation (H1). The relying-party
   setup is right (assetlinks only, a committed demo keystore). The gates'
   protocol is good; the owner's availability is the schedule's hidden
   dependency (M10).
6. **The schedule.** The critical path and its 24–36 weeks are credible as
   arithmetic; 7.18 at 6–10 weeks for a split on two shapes with forgery
   gates per family is optimistic by 2–3 weeks, and 7.1 and 7.3 by a week
   each (L7). The parallelism is real but collides in `pvm/proof` (M4).
7. **Simplicity.** The plan is near as simple as its goals allow. Cut the
   challenge route (L4) and the epoch (M7); keep the pay statement as H3
   of the first review left it. The biggest complexity the slice adds is
   S23's second re-pin; its exit criterion is what keeps it from becoming
   a fold redesign (H3).
8. **Missing.** The ring's freshness rule (H2), the divergence guard and
   the clone/backup runbook (M1), the handoff's target and damper (M2),
   fuzzing at ingress (M3), the per-format cap (M5), the fixed-trace rule
   for device kernels (M8), the owner's phone budget (M10), and the
   `path` access rule (L2).

## Decisions to revisit

- **S25 (the stable PRF handle)** stands, but it conflicts with pin I's
  scope and buys nothing unless the re-founding runbook re-seeds the tree
  from the ended space's digests (H1). The owner should confirm both: the
  scope carries the `SpaceId`, and re-founding imports `member` digests
  with no member action. If the owner would rather members re-enroll,
  S25 should be dropped and the `SpaceId` put back into the PRF input,
  which closes the handle-copy linkage outright.
- **S23 (the chip and the levers into format 41)** stands, with its gate
  moved to 7.18's first day and an explicit exit if the kernel leaf
  overflows 2^16 (H3). The owner should say now whether a fold-shape
  change (`p2` at 2^17, a new `H_FOLD`) is acceptable at all in this
  slice; if not, the split is device-only on overflow.
- **S11 (equivocation fully terminal)** stands; the owner should accept
  M1's divergence guard as part of it, since without it an apply bug or a
  cloned store, not only a stolen key, ends the space for good.
- **S7 (7.14 beside M3.9 from day one)** stands only with 7.8 split (M4);
  otherwise 7.14 should start after 7.8.

No decision among S1–S31 is unsafe on its own; the two contradictions are
S25 against pin I's scope (H1) and pin I's size cap against pin J's budget
(M5), both resolved by the fixes above.
