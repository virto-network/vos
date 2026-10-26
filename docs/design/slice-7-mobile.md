# Slice 7: simplify and scale, then proofs on the phone

Plan, draft 4, with the owner's answers and Fable's review of draft 3
folded (2026-10-25), and the owner's S34–S52 since
(2026-10-26). It takes the owner's slice-7 decisions S1–S52
(`research/slice-7/owner-decisions.md`) and the first real phone run
(`research/slice-7/phone-fairphone6-s5kit.txt`).
Slice 6's decisions 1–18 stand, except those S9–S17 reverse ("Decisions"
lists each). Two questions stay open: S3's gate after 7.0a (S20) and the
credential parameters after 7.12 (S29).
- **The architecture** is `proving.md` (draft 6) §3–§8, `identity-and-authority.md`
  §5–§7 and slice 6's pins D–F (`slice-6-on-chain.md`). The research is in
  `research/slice-7/`: `simplify.md` (pin D inventoried, eleven candidates
  C1–C11, all taken), `device-params.md` (the device and credential
  parameters counted under masking (c)), the phone run, and
  `teammate-note.md` (what changes for the Kreivo teammate, S19).
- **This slice builds three milestones:**
  - **M3.9, simplify and scale:** the anchoring protocol simplified by
    C1–C11; a scale test across the owner's LAN;
  - **M4, the credential AIR:** slice 6's re-pin batch; a credential actor
    keeping a Poseidon2 tree in its own rows; the credential AIR; the
    node's binary API and its gateway (S41); the credential verifier at a
    space's ingress; the device library and a demo in s4's Android client
    (S40);
  - **M5, the device profile:** the general zkVM on the phone, the auth
    statement in at most 1 s on the Fairphone 6 [decided, S3], **a gate at
    real risk** (M5's outlook, below); then the Poseidon2 chip and M5's
    levers into the node's segment format too, the slice's second re-pin
    (S23).
- **Out of the slice:** M6, the signature chips (S1); a Wasm or browser
  prover (S4); iOS (S5); the Kreivo pallet (the teammate's) and its chain
  transport (after the slices, decision 12d).
- **Its log:** `slice-7-progress.md`, beside this plan.

Tags as in slice 6: [measured] by a spike or a step; [model] by the
security tool or a fit; [est] arithmetic on measured numbers, not run;
[decided] the owner's; [proposed] open to review.

## Changes from draft 3

Fable's review of draft 3 (`plan3-fable.md`, "ready after fixes"), every
finding folded, and the owner's S32–S33: the scope carries the `SpaceId`
and the runbook re-seeds the tree (H1); older roots expire (H2); the leaf
count on 7.18's first day, no fold-shape change (H3, S32); the divergence
guard (M1); `Unlisted`'s target and damper (M2); the PoW first and fuzzing
at ingress (M3); 7.8 split (M4); per-format size caps (M5); the scale
harness's host facts (M6); no epoch (M7); a witness-independent device
trace (M8); 41 recounted (M9); nine planned phone sessions (M10, S33); and
the eleven lows.

**Since draft 4:** 7.7 pinned G, I, K and L in the design docs; the owner
answered its questions and two more (S37–S44): the ledger's `rekey` and
`freeze`, and a gate on a membership-and-payment proof (S37); paths
refreshed apart from proofs (S38); a duplicate answered `Replayed` (S39);
the demo in s4 (S40, 7.13); the node's binary API and a gateway, a new
step 7.10b (S41); the Keystore's HMAC key and a security key as the
secret's sources, no passkeys (S42, pin K, 7.0b); the `once` guard
(S43); 7.11's rate gate a bound per thread (S44). Fable's review of 7.7
(`research/slice-7/7.7-fable.md`, "fix-then-merge") folded with the
owner's answers S46–S51: signed operator requests, socket-only until
built (S46); the `once` row only on `Ok` (S47); the facility's own form
for the payee and the amount (S48); a `vos-api` SSH subsystem for paths
and time (S49); 7.10b beside 7.9 and 7.10 (S50); the input's tag
`"vos/device/input/v1"` (S51); the demo's ledger, the library's `root`
helpers and 7.10b's frame grammar pinned.

**Earlier drafts:** draft 2 folded the Opus review of draft 1
(`plan1-review.md`); draft 3 took the owner's answers S6–S31.

## Goals

1. **A protocol a reviewer holds whole:** pin D as the owner trims it,
   one anchor rule written once, one outcome enum on the node.
2. **Scale measured, not extrapolated:** a scripted test on the owner's
   LAN, a million simulated users and tens of thousands of agents in one
   space, the targets met or each gap recorded with its lever.
3. **Credentials on the phone:** a device secret from a key the phone
   never exports (the Android Keystore's, or a security key's); masked
   auth and payment proofs on the Fairphone 6, verified at a local space's
   ingress; a demo in s4's Android client end to end.
4. **A node that speaks one binary API:** its HTTP, public TLS and
   front-end concerns in a gateway that holds no authority (S41).
5. **The general zkVM on the phone:** the auth statement under the device
   profile, masked, in at most 1 s and 1 GiB on the Fairphone 6 [decided,
   S3], or the gap measured lever by lever for the owner to judge.
6. **Two program-id re-pins and one blob lock, each one commit:** slice
   6's pvm-internal items early (7.8a), its agent-side items with
   `blobs.lock` after 7.3 and 7.11 (7.8b); the node's segment format 41
   late (7.21), with what S32's count lets in.
7. **Every item slice 6 carried** placed in a step or carried by name.

**No value rides on a proof in this slice:** the external audit comes
first (slice 6's decision 14); slice 7 adds the credential AIR, the
device shape, the Poseidon2 chip and the CPU split to its scope.

## What exists at the start

- **vos-core** at `f83f744b` (slice 6 accepted); the Stwo pin olanod/stwo
  `c3ec981`.
- **Slice 5's mobile spike** (`spike/s5-mobile`, `ea539e9e`): the auth and
  pay kernels, a floor seam (no page boundary; a cost proxy that does not
  verify) and the phone kit; **503 commits behind**, on the pre-hardening
  AIR and format 24's Blake2s channel.
- **Measured on the gate device** (2026-10-25, the kit's configuration
  `2:38:20`: log blowup 2, so blowup 4, 38 queries, PoW 20; unmasked):
  as built 6.2–6.5 s at 4 threads (2.0 GiB), 5.1 s at 8; the floor
  2.6–3.0 s at 4 threads (0.9 GiB), 2.59 s on the 4 big cores, 2.2 s at
  8; x86 1.72 and 0.84 s at 4 threads. Every proof byte-identical to
  x86's. The ARM factor is about 3.5× [measured].
- **Found while planning** [model, `device-params.md`]: format 37 counts
  61.86 proven bits under masking (c); at 86 queries every masked
  component pads to 2^12 rows, not §8's 2^11.
- **Not built:** a Blake2s-M31 channel in `pcs.rs`; masking for the
  segment chips; any Android or Keystore code; a node API apart from HTTP,
  or a gateway; an operator path to the representative; a multi-host
  driver.

## How every step runs

- **A brief per step,** from this plan and the design docs; an
  implementing agent works from it alone, at medium effort.
- **Reviews:** one Opus review of every step's diff, folded before the
  next step builds on it; Fable at each milestone's end and the slice's
  end. Steps marked **(S)** change soundness, the protocol or a state
  layout: Fable checks them first. Review latency is outside the
  estimates; the owner is not paused for between steps.
- **Gates:** `just check` per step; at each milestone's end `just ci-full`
  (fuzz a minute a target, leakage at medium N) and the checker loop; at
  the slice's end `just slice-gate` (leakage at full N, fuzz five minutes
  a target), the checker loop, `just e2e-chain`, the kit's sync check, the
  scale test's final run and the phone gates. Heavy runs one at a time
  under `systemd-run --user --scope -q -p MemoryMax=12G -p MemorySwapMax=0 nice -n 10`,
  `TMPDIR` on disk, builds at `-j8`–`12`.
- **Phone gates** (the s5 kit's runbook): two static aarch64-musl bench
  builds, neither shipped: a timing build (masks from the OS) and a
  `seeded-masks` build checked byte for byte against x86; battery at least
  50%, below 35.0 °C at each round's start, saver off, stay-on, out of its
  case; 3 rounds of 5, 60 s apart; the gate the median of the rounds'
  medians, the 95th percentile beside it; each proof verified on the phone
  and on x86; JSON lines in `research/slice-7/`. The coordinator runs it
  over adb when the owner attaches the phone and agrees.
- **Phone sessions** [decided, S33]: the Fairphone 6 is the only device;
  its sessions are batched and asked for a week ahead, each with its date
  window and list. Between them, x86 timings scaled by the ARM factor
  (re-measured each session) and qemu-aarch64 (byte-identity,
  verification) serve iteration; neither is a gate.

  | session | when | what |
  |---|---|---|
  | P1 | 7.0a's end | the baseline and masked proxy; 7.0b's secret sources, across uses, a reboot and a security key's re-plug |
  | P2 | 7.12 | PG1 and the grind's 95th percentile (S29); the demo's first run |
  | P3 | 7.13's end | PG3 recorded |
  | P4 | 7.16 | the device parameters' candidates |
  | P5 | 7.17's end | levers 1–4 together |
  | P6 | 7.18, mid-way | the CPU split's first phone numbers |
  | P7, P8 | 7.18's (or 7.19's) exit, a day apart | PG2, twice |
  | P9 | 7.23 | PG1–PG3 on the final build |

  The critical path assumes each session within a week of its ask.
- **Rules:** slice 6's (`slice-6-on-chain.md`, "How every step runs"):
  commit on `vos-core`, push after reviewed milestones, the fork's pushes
  after Fable, no Kreivo code, timeless comments, no `#[ignore]`, no
  Co-Authored-By, kill by PID only, fix pre-existing failures; every
  measured number tagged in `slice-7-progress.md`.

## The pins

Specs the steps implement, [proposed] unless tagged. Pin D′ is M3.9's;
G–L are M4's and M5's.

### Pin D′: the anchoring protocol, simplified

`simplify.md` §4 states pin D under all eleven candidates, all taken
[decided, S8–S18]:
- **What stays:** one root per `(space, w)` at a venue, a second root as
  evidence that stops the space, the honest node's own anchor sent as
  evidence; the anchor's signature by a listed key; `Last < w < now_w` by
  the venue's time; `MaxRootAge`; `Seen`; the served path's checks in
  refine; decision 2's rule.
- **The venue core** (C6): `vos_anchor::venue`, `no_std`, the registration,
  anchor, `anchored`, `seen_expiry` and freshness rules as pure functions
  over a `VenueState` trait; `ModelVenue`, the JAM service's accumulate
  and the Kreivo mock call it; the kit vendors it; `spaces-pallet.md` §6.1
  says the pallet calls it.
- **The node's outcome enum** (C5):
  `enum AnchorOutcome { Taken, NotYet, Never(u32), Unlisted(u32), Stopped(u32) }`,
  the raw venue code carried for the log (`Stopped`: the space ended or
  blocked); one mapping table per client, tested against every venue
  code. Submits: `enum SubmitOutcome { Accepted, Refused(u32), Retry }`, a
  repeat `Accepted` at one site.
- **`Unlisted`'s handoff:** the leader transfers its leadership
  (`vos-raft`'s `transfer_leadership`) to a replica whose node key the
  client's last listing holds; at most one handoff a window of the
  space's clock, per node, across its leaderships; with no replica
  listed, it alerts and waits, no handoff.
- **What a client still reads:** the space's status, `AnchorKeys` (the
  handoff's target; on Kreivo it tells a delisted authority's `Payment`
  refusal from an exhausted budget) and `Last`/`Anchors[w]`; on its own
  thread, cached for the batch thread (slice 6's F2).
- **The replicated anchor row** (C3, C11): the representative's close
  writes `anchor(w) = S_w` in the commit that finishes its cut's build
  (the cut fixed by the committed log, so the same bytes on every
  replica; not the agent's apply of `Input::Close`, which would change
  the agent image; `slice-7-progress.md`, 7.2) for a window some agent
  reported, kept for `MaxRootAge`; its leader signs only those rows,
  never a root from the batch under proposal, in window order, with its
  node key (C2); nothing is handed back.
- **The divergence guard** (S11, S34): before sending an anchor the venue
  would store as evidence, the leader asks its followers for their
  `anchor(w)`. A quorum of the group holding its row decides: the
  evidence goes, each dissenting replica alerted by name with its root
  (one equal to the venue's held root names the equivocator). Without a
  quorum it sends nothing, settles nothing, and asks again every 2 s,
  alerted once. A dissent alone never settles the window. A restored
  backup or a cloned store counts as a compromised node key
  (`docs/operations.md`): the node is replaced before the space re-founds.
- **Equivocation ends the space** (C4, S11): the evidence is stored, the
  status becomes `Ended`, its roots are refused from then on, at every
  venue, with no resume and no revive; the record is a tombstone the venue
  never prunes, so a replayed registration is refused; the registration
  deposit is released to the sovereign on `Ended`, and the controller's
  `dispatch_as_sovereign` stays callable, so the funds leave (the
  existential deposit stays). The space re-founds under a new `SpaceId`;
  the re-founding runbook installs the new credential actor with the same
  handle (pin K) and re-seeds its tree from the ended space's `member`
  digests, with no member action; its Clerk pairs reset.
- **No migration** (C1): the Clerk's counterparties share a venue for good
  [decided, S9]. Registering at one venue is the space's discipline, which
  no venue enforces: a founder may register the same genesis at two, and
  neither sees the other (with the same roots a statement is handled at
  both; with different roots the space forks unseen).

### Pin G: the credential actor and its Poseidon2 tree

The full spec is `identity-and-authority.md` §6 (the actor, its rows, its
ring, its methods) and `proving.md` §8 (the hash, the tree); pinned by
7.7.
- **What it is:** `vos-credentials`, a library actor installed in the
  agent whose methods it guards (the demo's: the ledger's agent), one an
  agent, found through the system row `credentials → instance` its install
  writes. Its tree is a **positional sparse Merkle tree** of Poseidon2-M31
  compressions, depth 32, in its own plain rows: `slots` (a `member`
  digest → its slot; freed slots reused lowest first through an ordered
  `free` table), `nodes` (level, index → the non-empty digests, level 0
  the leaves), the empty subtrees' digests as constants.
- **The hashes:** each one `0x402` call (pin H), `C(l, r)`: the VOS host
  serves it natively, a JAM-deployed agent pays the shim's software
  permutation (about 15,800 instructions); so VOS ≡ JAM holds, and the
  tree is as deterministic as any row. `leaf = C(T(leaf), member)`, the
  slot not hashed (the path places it); a node `C(left, right)`; the empty
  leaf eight zero words; a tag `T(name)` the block `[t, 0, …, 0]`, `t` from
  `BLAKE2b-256("vos/p2/" ‖ name)`. 33 calls a write.
- **Roots:** a replicated ring of the last 64 `(root, since)`, one entry a
  batch time that changed the tree. **Freshness** (the Fable review's H2):
  a root is accepted while it is the newest, and for `ROOT_MAX_AGE`
  (10 minutes) after it was superseded (the next entry's `since`), by the
  replica's latest applied batch time at ingress and by the batch's time at
  apply, so a revocation takes effect within it at every replica; the
  ring's count only bounds storage.
- **The handle** (pin K, S25): 32 bytes the founder draws once, set at the
  actor's install and served by `handle()`; a re-founded space's actor is
  installed with the same handle.
- **Methods:** `enroll`, `enroll_many` (the re-founding re-seed),
  `invite`/`claim` (the demo's enrollment, the invitation naming the
  digest), `revoke`, under the role `registrar` but `claim`; the queries
  `path(member) → (root, slot, siblings[32])`, `root()` and `handle()`,
  any caller, under a query's limits. **What `path` reveals:** asking by
  key tells the operators which member digest is online, and from which
  address; the library refreshes its path apart from its proofs (when
  `root()` moves and on a timer, never just before a proof) [decided,
  S38], so a fetch's time says nothing of a proof's. The leak is reduced,
  not closed: `Anonymous` hides the member from the log's readers and from
  other agents, not from operators (`identity-and-authority.md` §7's
  threat model). Recorded in `node/SECURITY.md`, new in 7.11 for the
  node's credential surface (`pvm/proof/SECURITY.md` stays the
  prover's).
- **`RootKind` and the representative are untouched:** no venue checks a
  Poseidon2 root in this slice; a later cross-space credential proves its
  root's place under `S_w` by a Blake2b path outside the proof, its issuer
  opting in to report every window (C10).
- **Across agents:** a guard reads only its own agent's state, so a
  credential guards methods of the agent its actor lives in; credentials
  across a space's agents wait for the identity agent replicated on every
  node (`identity-and-authority.md` §6).

### Pin H: the Poseidon2 host call and chip, and segment format 41

- **The call:** `0x402` (`ECALL_POSEIDON2`), dispatch 102: φ7 points at 64
  bytes (16 M31 words, little-endian u32, each `< p`; a word ≥ p, p itself
  included, traps the live call), φ8 at 32 bytes written with the 8-word
  output of `compress`; no other effect. Served natively by the VOS host
  at a price measured in 7.9; on JAM the guest shim computes it in
  software on `WHAT`.
- **The chip** (7.15), in the device format, and in the node's segment
  format as S32 allows [decided, S23, S32]: one permutation a row, `p2`'s
  arithmetic (`permutation_columns`, the S-box pair) as a
  `BuiltInComponent`, about 300 main columns at degree ≤ 3; memory-access
  lookups for the 64 bytes read and 32 written; each input word
  range-checked below p, so a word the live call refuses has no proof; a
  `Poseidon2Call` relation from the CPU's `IsP2Ecall` selector.
- **Format 41, the node's segments** (7.21): format 35's AIR, the page
  boundary kept, with what S32's count allows (the chip and M5's levers if
  every kernel leaf stays within 2^16 `p2` rows at 40 queries; else the
  chip alone; else no 41 this slice; **no fold-shape change**); its
  parameters recounted on its own shape; 35 retired then. Until 7.21 the
  nodes prove under 35, byte for byte, and `derive` admits `0x402` in
  device kernels and handlers alone.

### Pin I: the credential statements and their verifier at ingress

The full spec is `proving.md` §8 (the hashes, the statements, the
format) and `identity-and-authority.md` §5 (the request, the binding, the
guards, ingress's checks and their codes, the apply rule, the origins);
pinned by 7.7.
- **The AIR:** a recursion-AIR circuit (recair's `Context` and gadgets)
  over the `p2` and `qm31` components, a fixed wiring per statement, so
  its circuit hash is its program id. Two components at least, so the
  claimed sums are blinded (a one-component masked set is not).
- **Format 42, credential proofs** (`device-params.md`): masked (c),
  Blake2s-M31 channel, **blowup 4, 43 queries, PoW 20**, interaction PoW
  8, fold step 1, affine DEEP batching if the fork's Blake2s-M31 path takes
  it, else by powers; at least 62 proven and 100 conjectured bits on its
  masked shape (62.69 and 106 [model]); `h = 512`, every component at
  least 2^11 rows. If 7.12's grind has a 95th percentile above 50 ms on
  the phone [decided, S29], the format is **44**, the same at 47 queries
  and PoW 16 (62.66 and 110 [model]), and 42 is retired: a number names one
  set of parameters. 30, reserved at an unmasked count, is retired
  unregistered.
- **The scope,** namespaced by the verifier and its space (the Fable
  review's H1):
  `scope = C(T(scope), W(BLAKE2b-256("vos/cred/scope/v1" ‖ space ‖ agent ‖ instance ‖ name)))`,
  `W` a 32-byte digest's eight 31-bit words, computed by ingress from the
  method's guard; no two agents' "login", in one space or two, share a
  pseudonym, even for a member whose secret two spaces share (pin K).
- **The binding:** `binding = C(T(binding), W(b))`,
  `b = BLAKE2b-256("vos/cred/binding/v1" ‖ space ‖ agent ‖ instance ‖ method ‖ program ‖ kind ‖ SCALE(arguments) ‖ nonce ‖ expires_ms)`:
  a proof authorizes one call, in one space, under one statement.
  `SCALE(arguments)` is the codec's, a `u32` little-endian length then the
  bytes (`node-api.md` §10).
- **Auth** (`CredentialKind::Auth = 0`), public
  `(kind, map_root, scope, nullifier, binding)`, `kind` one word and each
  digest 8; private `s`, the slot's bits and its path. Proves
  `leaf(member(s))` under `map_root` and
  `nullifier = C(C(T(nf), s), scope)`; 36 permutations.
- **Pay** (`CredentialKind::Owner = 1`), public `(kind, owner, binding)`;
  private `s`. Proves `owner = C(T(owner), s)`: a post-quantum
  authorization by the owner of a row, one permutation. No path, no range
  check: the ledger debits the live row at apply, so its handler compares
  the row's current `owner` with the proof's, and a previous owner's proof
  fails once the row changes hands. A hidden payer waits for full privacy
  (`identity-and-authority.md` §8). Revocation does not stop payment: the
  ledger's `rekey(row, owner)` and `freeze(row)`, under an operator role,
  do [decided, S37].
- **Membership and payment together,** measured, not admitted [decided,
  S37]: a third circuit proving auth's leaf, path and nullifier and
  owner's digest from one `s` (37 permutations), built in 7.10 and timed
  on the phone in 7.12, so the later private payment's statement is known
  to fit the budget: a floor for a shielded spend, whose notes, values
  and ranges cost far more. No `CredentialKind` and no ingress path in
  this slice.
- **The request:** a request of the node API (7.10b), addressed to its
  agent as every agent request there is,
  `Credentialed { instance, method, arguments, nonce, expires_ms, format, public, proof }`,
  no session (the reserved session-less input kind,
  `identity-and-authority.md` §15 step 0); a frame kind of its own, so the
  node sizes the frame (1.5 MiB plus `cap::REQUEST` plus 4 KiB) before
  decoding it. The node's clock is the API's `Time` request, unsigned: a
  relay that lies about it costs the client a new proof and cannot
  extend a proof's life, since ingress checks the expiry by its own
  clock. A gateway translates `POST /agents/{id}/credentialed` and
  `GET /time` onto them and holds no authority: every check below is the
  node's.
- **Ingress checks, in order** (`identity-and-authority.md` §5's table,
  each a `Rejected(Credential(code))`, the codes in check order): the
  frame's size; the decode; the
  agent served; the space has a genesis; the format; the size per format
  (42 or 44: 512 KiB; 43: 1.5 MiB; the log carries the call and origin,
  never the proof, so `cap::REQUEST` is unchanged); `expires_ms` within
  120 s ahead of the node's clock; the method's credential guard; the
  kind; for auth, the scope; the binding; the binding digest not recorded;
  for a `once` guard, the nullifier not recorded in its scope; for auth,
  `map_root` in the ring (else retryable, the identity replica's lag
  rule) and fresh by `ROOT_MAX_AGE`; a verification slot; then the proof,
  on an executor, **its PoW checked before any decommitment**. **Load:**
  the node's connections and a verification budget (past it, `Busy`), no
  bucket per scope or method to drain; the gateway adds its own limits
  before authentication (S41).
- **At apply:** refused if `expires_ms` is before the batch time, if the
  binding digest is already recorded, for auth if the root is stale by
  the batch time, or for a `once` guard if its nullifier is recorded in
  its scope; else the digest is recorded until `expires_ms` plus 60 s by
  batch time, whatever the method then does, and the method runs; a
  `once` guard's nullifier is recorded for good only if the method
  returned `Ok`, in the same apply [decided, S47]. So a proof replayed at
  another node runs nowhere twice. A duplicate is answered
  `Refusal::Replayed` (refine's enum; `CredentialRefusal::Replayed` at
  ingress), without the first call's outcome [decided, S39].
- **The origin logged:** `Anonymous { scope, nullifier }` for auth (a
  pseudonym in its scope, stable) and `Owner(digest)` for pay,
  `Principal`'s indexes 3 and 4; never the proof
  (`identity-and-authority.md` §5). Guards:
  `#[msg(credential = Auth("login"))]`, `#[msg(credential = Owner)]`, in
  `MethodSchema::credential`, whose `Auth` carries the device kernel M5
  names, so M5 moves no pinned blob.
- **The `once` guard** [decided, S43]: `#[msg(credential = Auth("vote"), once)]`
  admits a nullifier once in its scope, the scope's (space, agent,
  instance, name) by construction. Apply records it in the system row
  `once(scope ‖ nullifier) → t`, the batch time of its admission, kept for
  good, only when the handler returns `Ok` [decided, S47]: a call the
  handler fails or refuses leaves the member free to try again with a new
  proof. A repeat of an admitted nullifier is refused,
  `CredentialRefusal::Once` at ingress and `Refusal::Once` at apply. A
  new round takes a new name ("vote/2026-11"), so a new scope.
- **Gates:** the native verify of a credential proof at most 10 ms on one
  x86 core; a proof with a wrong PoW refused in under 1 ms; fuzz targets
  for the `Credentialed` decode and the format 42 and 43 verifiers in
  `just fuzz`.

### Pin J: the device profile, and format 43

- **The shape:** one segment, at most 2^16 steps; the shared chip set (the
  Poseidon2 chip and M5's levers, whether or not S32 lets them into 41)
  without the page-Merkle boundary (BLAKE2B_BOUNDARY, MEMORY_PAGE, MEMORY_MERKLE,
  MEMORY_ROOT_BOUNDARY); the run bound by
  - code: PROGRAM_MEMORY, preprocessed;
  - first touches (`ts = 0` ledger entries): the data region from a
    preprocessed data table; stack and heap zero; elsewhere refused;
  - read-only pages: a preprocessed permission table per region;
  - arguments: the witness-input precompile; the output: the io-hash in
    φ9..12 only, no memory root out.
- **Masked** (c) over the segment chips (7.14): the active-chip mask, a
  finalize hook for the 14 chips that finalize unpaired, a per-component
  `h` by the component's offsets (`|O| = 1` components at half the
  floor), the fixed tables padded to the floor.
- **Format 43, device proofs:** Blake2s-M31 channel, parameters chosen by
  7.16 from `device-params.md`'s candidates (blowup 2 with 86–87 queries,
  4 with 43, or 4 with 47 at PoW 16, 8 with 29), at least 62 proven and
  100 conjectured bits on its masked shape. 37, reserved at an unmasked
  count, is retired unregistered.
- **The device program id:** the format, the chip mask, the log sizes and
  the preprocessed roots (program memory, data table, permissions), as a
  segment program's; computed at install, never taken as submitted.
- **A witness-independent trace** (the Fable review's M8): the prover pads
  every chip to the program id's log sizes and fails on a run that
  exceeds them; a device kernel is written branch-free (the path walked
  with selects), so its proof's shape never depends on the witness.
- **What a device proof authorizes at ingress:** exactly what an auth
  credential proof does. A device kernel is an `#[attestable]` method whose
  `public_args` are pin I's auth words, the SCALE encoding of
  `CredentialPublic::Auth` (its kind byte, then `map_root`, `scope`,
  `nullifier`, `binding`), and whose output is empty; ingress takes the
  words from the request, recomputes the io-hash, verifies the proof
  against the device program id of the kernel the method's guard names
  (`device`), then runs pin I's auth checks (the binding naming that
  program) and logs the same `Anonymous` origin. Payment stays a
  credential proof. Nothing else a device proof states is admitted in this
  slice.
- **Budgets on the Fairphone 6** [decided, S3, S20, S27, S28]: the auth
  statement at most **1.0 s** (median, automatic threads), peak resident
  at most **1 GiB** (target 768 MiB), the proof at most 1.5 MiB; verify at
  ingress at most 40 ms on one x86 core.

### Pin K: the device secret from a secret source

The full spec is `proving.md` §8 (the derivation) and
`identity-and-authority.md` §7 (its threat model); the sources are the
owner's [decided, S42].
- **The source:** a keyed HMAC-SHA-256 whose key the device never
  exports, evaluated once per use after the user's consent:
  - **by default, an Android Keystore HMAC key:** `KEY_ALGORITHM_HMAC_SHA256`,
    purpose sign, user authentication required at every use (biometric
    or the device's PIN, `setUserAuthenticationParameters(0, …)`, through
    the platform's `BiometricPrompt` with the `Mac` as its crypto
    object), StrongBox-backed when the phone has it (recorded), not
    invalidated by a new biometric enrollment; Android 11 (API 30) or
    later. `Mac.doFinal` returns a `byte[]`, zero-filled once copied;
  - **optionally, a security key's `hmac-secret`,** by CTAP2 directly
    through YubiKit, over USB or NFC, always with user verification (its
    PIN) and a touch: CTAP2 keys a credential's `hmac-secret` apart with
    and without user verification, so a use without the PIN would derive
    another `s`. One credential for every handle (the salt varies), made
    under one pinned `rpId` constant, `"vos.device"` (a CTAP2 string, not
    a WebAuthn relying party); its credential id is the stored reference.
    The salt is the input below as it is, no WebAuthn client prefixing
    it.
  - **Not in this slice:** Credential Manager, passkeys, Play services and
    the Play Store; a source that spans devices is later work.
- **The input:** `input = SHA-256("vos/device/input/v1" ‖ handle)`
  [decided, S51], the message the source's HMAC takes. `handle` is the
  space's stable handle (pin G), not its `SpaceId`, so a member's secret
  survives a re-founding [decided, S25]. The client shows the handle and
  pins it at the first enrollment. The device keeps only the **source's
  reference** (the Keystore alias, or the security key's credential id)
  beside the pinned handle.
- **The derivation:** `o` the source's 32-byte output;
  `w = BLAKE2b-512("vos/device/secret/v1" ‖ handle ‖ o)`;
  `s_i = u64_le(w[8i..8i+8]) mod p` for `i < 8` (bias below 2^-33 an
  element); derived again at each use, never stored.
- **What a space stores:** `member(s) = C(T(member), s)` in the
  credential actor, `owner(s) = C(T(owner), s)` in a ledger row; no
  epoch, which the device could not keep nor the actor check (the Fable
  review's M7): a revocation removes the leaf (pin G's freshness makes it
  take effect), a new source is a new `s` and a new leaf. The handle is in
  the derivation, so one source gives unlinkable secrets in two spaces
  with different handles.
- **The handle-copy linkage** (in `node/SECURITY.md`): a founder who copies
  another space's public handle makes a member of both hold one `s`, so
  the two spaces' operators can link that member's `member` and `owner`
  digests; the scopes carry the `SpaceId`, so nullifiers stay distinct.
- **Containment** (in `vos-device`'s own `SECURITY.md`, new in 7.12;
  `identity-and-authority.md` §7's threat model): the key stays in the
  Keystore (or on the security key); `o`, equivalent to `s`, crosses
  into the app's process at each use, as a `byte[]` the bridge
  zero-fills and the library zeroizes after copying. Code in the process
  during a use reads `o`. A lost key (a factory reset, the screen lock
  removed, a lost security key) is a lost `s`: the member is revoked and
  enrolls again, and the ledger's `rekey` moves its rows (S37).

### Pin L: the device library

- **Crates:** `vos-device` (the prover API, `std`, aarch64 and x86_64),
  linked as a Rust crate by s4's Android client, itself a Rust `cdylib`
  (S40): no JNI shim of VOS's own. Built for `aarch64-linux-android` with
  `cargo-ndk` against the s4 client's NDK (28.2), mimalloc, no other C
  dependency. The only Java is s4's: its `KeystoreBridge` (pin K's source)
  and YubiKit, already in s4.
- **The API** is `proving.md` §8's, pinned by 7.7: `source_input`,
  `derive_secret`, `member`, `owner`; a `Call` (space, agent, instance,
  method, arguments, a nonce from the OS, `expires_ms`) from which the
  library computes the scope and the binding itself; `Prover::prove_auth`
  (the secret, the `AuthWitness` from `path`, the guard's scope name, the
  call), `prove_owner` (the secret, the call) and M5's `prove_kernel`;
  `verify`; and the wire helpers, node-API requests and their answers
  (`time_request`, `time_answer`; `path_query` and `root_query`, each
  addressed to the agent's id and signed over its 32-byte identity by a
  key drawn for it alone; `path_answer`, `root_answer`; `credentialed`),
  so neither the client nor the gateway encodes a credential's bytes.
  `prove_auth`
  checks its witness before proving. **Paths** are refreshed apart from
  proofs (pin G, S38): `PathKeeper` holds the current path and says when
  to fetch again (`root()` moved, or a timer with jitter), and a proof
  uses the path it holds. `Threads::Auto` is rayon's even split over
  every core until 7.17 weights work by core class; `DeviceError` names
  what failed and no value. No logging of
  witnesses; the library has no `seeded-masks` (pin C's build check
  covers it).

## M3.9: simplify and scale

Two tracks from the first day: the simplification (7.1–7.3) and the scale
harness (7.4–7.5) meet in the scale runs (7.6). The probes (7.0a, 7.0b),
M4's 7.7, 7.8a, 7.9, 7.10 and 7.10b and M5's 7.14 run beside them
[decided, S7, S50].

### 7.0 The docs, the picks and two probes

- **7.0 The docs:** the owner's answers into `owner-decisions.md` and
  "Decisions"; `slice-7-progress.md` opened; `proving.md` §8's floor and
  §11's rows corrected; `core-model.md`'s "Draft 5" heading (slice 6's L8).
- **7.0a The device baseline on today's AIR** (a spike, throwaway code):
  slice 5's floor seam and statements rebased onto `f83f744b`; on x86 the
  as-built and floor shapes at log blowup 1 and 2, 4 and 8 threads, and
  **a masked-cost proxy** (every column committed at its log size + 1, the
  composition at + 2, as masking (c) commits); the kit on the phone
  (session P1). **Output:** today's starting point, the masking factor on
  this shape, the proof's bytes at blowup 2 with 86–87 queries against
  pin J's 1.5 MiB; M5's outlook redone, for the owner's call on S3's gate
  (S20). The proxy hashes the undoubled tree shape, omitting the doubled
  leaf layer's hashing that dominated the wrap's factor: it is a floor on
  the masking factor, not an estimate. **Estimate:** 1–1.5 weeks.
- **7.0b The secret sources on the gate device** (a probe, session P1,
  throwaway code in s4's Android host): a Keystore HMAC key under pin K's
  spec, used through `BiometricPrompt` with its `Mac`; `Mac.doFinal` of
  one input equal across uses and after a reboot; the key's StrongBox
  backing and per-use prompt recorded; its output a `byte[]` the bridge
  zero-fills. A security key's `hmac-secret` through YubiKit's CTAP2
  session under pin K's `rpId`, with user verification, over USB and NFC,
  equal twice and after a re-plug. No relying
  party and no `assetlinks.json` [decided, S42; S6 reversed]; no Play
  services. **Fallback:** if StrongBox refuses a per-use HMAC key, the
  TEE-backed key, recorded; without a security key at hand, the Keystore
  alone. **Estimate:** 2–3 days.

### 7.1 The venue side simplified (S)

- **What:** C6 (the venue core), C1 (no migration), C4 (equivocation
  ends the space, a tombstone, no resume), C8 (registration from the next
  window) and C7 (rooted statements only) at `vos-anchor`, `vos-statement`,
  `ModelVenue`, the JAM statements service, the Kreivo mock and client,
  and jam-dev's client; `spaces-pallet.md` v2 and the conformance vectors
  regenerated once (S19; `teammate-note.md` sent now): the teammate's
  first drop (then 7.8a's, 7.8b's and 7.21's).
- **Folded:** slice 6's F2 (`behind()`'s read on the batch thread goes with
  the client's pre-checks), F3 (gone with resume), L4 (strict ed25519,
  and a small-order key refused at registration and when added, with a
  vector), L3's migration half, item 74 (`forward_venue!`), item 29 (the
  control tests), and the info items: duplicate founding keys
  `BadGenesis`, the service's storage read trapping on an undecodable row.
- **Tests:** the core's own suite (every rule, every refusal) run against
  each venue's state; G1–G19 renumbered as the picks leave them; the
  fixtures judged alike at every venue; an equivocation ending the space
  at each venue (status `Ended`, the Kreivo index 3, 1 retired); the
  tombstone (an ended space's registration replayed, refused); the
  registration deposit released on `Ended`; `dispatch_as_sovereign` on an
  ended space.
- **Gate:** every venue calls the core; no anchor-rule logic outside it
  (a grep check in `just check`); the vectors regenerate byte for byte.
- **Dep:** 7.0. **Estimate:** 3–4 weeks.

### 7.2 The node's anchoring simplified (S)

- **What:** C2 (the node key alone), C3 (the replicated anchor row, no
  hand-back) and C5 (the outcome enums) in
  `node/host/src/leader/anchor.rs`, `anchor_keys.rs`, `vos-venue`'s queue
  and trait, the replica rule, the prover worker's submit mapping, and the
  CLI (`vos node anchor-key` removed).
- **Folded:** slice 6's L5 (jam-dev's `push` wedge) and the untested
  once-a-window recheck, both gone with the hand-back.
- **Tests:** anchors in order across a leader change; a deposed leader
  with an uncommitted close and a successor whose clock lags, both
  anchoring the same root; the divergence guard (a follower with another
  `anchor(w)`: no evidence sent, the alert); an unlisted leader handing
  off to a listed replica, which anchors; one handoff a window; no replica
  listed: an alert and a wait; a delisted node's replica refused and
  replaced; an equivocation ending the space; an aged window settled
  unsent; every venue code through each client's table.
- **Gate:** the checker loop with cuts and the representative; the
  leader's anchoring state and wait paths counted against `simplify.md`
  §4.
- **Dep:** 7.1. **Estimate:** 1.5–2.5 weeks.

### 7.3 Reads, reports and the worker's edges (S)

- **What:** C9 (no re-cuts), C10 (markers, cuts and reports only for
  windows a read waits on, and every window for an agent that opts in)
  and C11 (no anchor for an unreported window); the prover
  worker's carried edges: slice 6's M3 (a replica that installs a
  snapshot and leads recovers the unproved set from replicated state: an
  "attested, unproven" marker per cut it scans), M4 (`prune` ages out
  every unfinished job; an unfinished job's kernel pinned under
  `NODE_AGENT`), L6 (a)–(f); item 68 (a `closes` row that does not decode,
  quarantined with an alert, S30).
- **Tests:** a read served at its own window; `NotClosed` when the close
  misses it; an idle agent appends no marker; an opted-in agent reports
  every window; a window no one reported is not anchored; a leader change
  and a snapshot install with statements queued, each proved once.
- **Gate:** the checker loop; the cut's bench (a write with a cut pending,
  a cut's build with 100 proofs) within 10% of slice 6's.
- **Dep:** 7.2. **Estimate:** 2–3 weeks.

### 7.4 The scale harness

- **`tools/scale`** (`vos-scale`, a dev crate no shipped crate depends on,
  a `check-no-*` row), driven by an `inventory.toml` of x86_64 hosts (ssh
  address, role, a placement weight, the data disk, the cores to use):
  - `check`: ssh reach, the kernel (the JIT needs Linux ≥ 6.7; an older
    host is excluded or weighted down), clock offsets (refused above
    100 ms), free memory and disk, the disk's type, the CPU and its
    `scaling_governor`, the link's speed; a Wi-Fi host refused;
  - `deploy`: a static musl build of `vos` from a pinned `just release`,
    the guest ELFs, the space file and genesis, by `rsync`;
  - `up`, `down`: nodes under `systemd-run --user` with a memory cap;
    ingress over the node's built-in `--tls` with the node key pinned
    (plain HTTP serves loopback only), no certificates of the harness's
    own; `agents`: creation and installs by the weights; `drive`: the
    drivers (7.5);
  - `collect`: `/stats`, `/agents/*/status`, per-thread `/proc`, disk and
    network counters every 10 s as JSON lines; `report`: one directory a
    run, with its inventory, versions, host facts, summary, and the
    binding resource of each host at the knee (CPU, iowait, the NIC
    against its link speed).
- **Node changes it needs:** a `--config node.toml` exposing `Config`
  (executors, queue, linger, `max_inputs`, `ingress_connections`,
  elections, heartbeat); an admin route and `vos space representative` to
  create the representative; slice 6's L3 (`default-members` without the
  dev crates, so the release build is the one gated). No venue: the runs
  measure the window pipeline to the close, and anchoring is one call a
  window a space.
- **Gate:** a three-host run of 100 agents and 10,000 users from one
  command, collected and reported, on two of the owner's machines at
  least.
- **Dep:** 7.0. **Estimate:** 1.5–2.5 weeks.

### 7.5 The load model and its drivers

- **Users:** `U` simulated users, each an ed25519 key derived from a seed
  and an index (nothing stored), each with an account row in one of `K`
  ledger agents (by hash), a session opened at its first call and kept
  while it acts. **One rate drives every target:** a share `a` of users
  active at once, each making `r` calls a second while active; the
  offered load is `U·a·r` (at `a` = 5%, `r` = 0.1, 5,000 calls a second
  at a million users).
- **Agents:** `K` ledger shards (a test actor with a `CommittedMap` of
  accounts), `I` idle agents, and **a stand-in identity agent:** `U` rows
  replicated on every node host, written 10 times a second, its snapshots
  and catch-up measured.
- **Operations,** open loop (Poisson, latency timed from the scheduled
  send), users drawn Zipf(1.0): transfers (a **cross-shard share** `x`, a
  parameter: random payees give `x = 1 − 1/K`, about 98% at `K = 64`),
  queries on followers, workflows, and reads at a cut (`attest_at_cut`,
  the window pipeline without proving). Each kind reported apart.
- **Drivers:** each signs ahead, multiplexes users over at most 512 kept
  connections a node, and reports histograms, the rate and errors by kind
  every 10 s.
- **Not modeled,** stated in every report: the per-call identity read,
  credentialed calls (measured in 7.11), cross-space traffic, proving.
- **Gate:** one driver sustains 20k calls a second on one core-pair of a
  driver host; the operation mix within 1% of its target.
- **Dep:** 7.4. **Estimate:** 1–1.5 weeks.

### 7.6 The scale runs

- **The hardware** [decided, S35]: 3 nodes on `compumax`, each in its own
  unit with its own memory cap, cores and data directory; the drivers and
  the coordinator on the desktop, reaching the nodes over the LAN.
- **The runs,** in order, each 30 minutes steady after a ramp; every run
  that measures windows at `L` = 2 min (15 windows a run):
  1. **the per-replica cost:** 1k, 5k and 10k idle agents: RSS, idle wakes
     and the runtime thread's `late` by group count (the group inbox
     allocated whole at creation, and idle Raft timers, are the suspects;
     quiescing idle groups is the lever), fixed first if it binds;
  2. **the baseline:** `K = 64`, `U = 10^5`, `x` = 98% and again at 30%,
     the rate stepped to the knee: one host's knee, three nodes sharing
     its disk and NIC, not T2's. The rerun with the slowest host excluded
     needs four node hosts: recorded as not measurable (S35), to run when
     more machines exist;
  3. **users:** `U = 10^6`, `K = 64`, at the T1 rate, then at 80% of the
     knee;
  4. **agents:** `I` stepped 10^4 → 10^5 at the baseline's load;
  5. **faults** [decided, S36]: run 3 with one node's unit killed at
     minute 10, restarted at minute 15: **T5-partial**. The three nodes
     share one host, so re-election and rejoin are measured, a host's
     loss (its disk and link with it) is not; the host kill runs when more
     machines exist;
  6. **soak:** run 3 for 2 hours. An account's row is written at its
     first transfer, so the state grows through the first hour or so of
     U = 10^6 users: T6's flat RSS is judged after it, the growth reported.
- **Folded:** slice 6's item 53 (one snapshot per idle wake), item 58's
  performance half (the worker's table reads), and the levers the runs
  show binding (the runtime thread, the inbox, idle timers, the signature
  key cache), each a commit with its before and after; the ops notes
  (slice 6's L8, the clock-jump outage, catch-up by log) in
  `docs/operations.md`.
- **During timed runs,** drivers and the coordinator never share a node
  host: `check` refuses a node's machine that holds a driver or the
  coordinator, and admits three nodes on one machine (their caps summed
  against its memory, its disk's free space against all three).
- **Gate:** "The scale test" targets met, or each miss recorded with its
  measured cause and its lever (a step, or carried by name); C9's read
  fail rate at the LAN's real skew reported as a metric.
- **Dep:** 7.3, 7.5. **Estimate:** 2–4 weeks.

### M3.9 acceptance

- **Gates:** `ci-full`, the checker loop, the scale runs 1–6 reported;
  `simplify.md`'s counts redone after the picks.
- **Reviews:** Fable on 7.1–7.3 and the scale report; then a push.

## The scale test

**Hardware** [decided, S2, narrowed by S35]: the owner's desktop and one
other LAN machine, `compumax`, on a real network: 3 nodes on compumax
(each its own unit, cap and data directory), so every agent's 3 replicas
share that host; the drivers and the coordinator on the desktop. T1, T3,
T4 and T6 are measured as specified; T2 and run 2's rerun without the
slowest host need four node hosts, and are recorded as not measurable
until more machines exist.

**Users** are keys and account rows, not agents: an agent holds at most
65,536 live sessions (slice 3's cap), so a million users active within an
hour need at least 16 shard agents.

**Metrics:** per operation p50, p99 and p99.9 at the client and the
achieved rate; per node CPU by thread (the runtime thread above all),
RSS, idle wakes, fsync latency, disk and network bytes; leader changes;
the window pipeline (boundary to cut, report, close); clock offsets; cost
per user and per idle agent.

**Targets** [decided, S26], from the one rate (`a` = 5%
active at once, `r` = 0.1 calls a second each), checked after run 2 and
adjusted only by the owner:

| | target |
|---|---|
| T1 users | 10^6 users in one space at `U·a·r` = 5,000 calls a second, cross-shard share 98%, client p99 at most 50 ms, no session refused |
| T2 headroom | the knee at least 8× T1's rate (40,000 calls a second) on 4 node hosts or more, client p99 at most 50 ms below it, no leader lost: room for 8 million users at this rate, with `K` scaled to them (65,536 sessions an agent: `K ≥ 128`). Not measurable on S35's hardware (one node host): recorded so, the one host's knee reported beside it |
| T3 agents | 10^4 agents a space: idle cost at most 5% of a core and 64 MiB of RSS per 1,000 replicas (10^5 measured, a stretch) |
| T4 windows | at L = 2 min, 15 windows, with 1% of agents reading each window: every read served by `B_w + D + 10 s`, none `NotClosed` without a fault; the representative's work a window proportional to readers (C10) |
| T5 faults | a node host killed under load: every agent led again within 5 s, throughput back to 80% within 30 s, the host rejoined within 60 s of its restart. On S35's hardware, **T5-partial** [decided, S36]: one node's unit killed under load, the same bounds; the host kill re-run when more machines exist |
| T6 soak | 2 hours at T1: RSS flat within 10% after the first 30 minutes, p99 within 20% of the first half hour. Accounts are written at their first transfer: the RSS judged once the accounts' rows stop growing, their growth reported |

## M4: the credential AIR

7.7, 7.8a, 7.9 and 7.10 start beside M3.9 (S7); 7.8b waits for 7.3 and
7.11, the last steps that change the agent image and its ABI (the Fable
review's M4). 7.10's component set and 7.14's `MaskedComponents`
extensions touch `recair-air/src/masked.rs` apart: 7.10 needs none of
7.14's extensions (two recair components already mask, as `P2Only` does)
and adds its set in a file of its own.

### 7.7 The design round

- **What:** pins G, I, K and L checked against the code and the owner's
  answers (S21–S25, S29): the actor's rows and its ring, the
  statements' exact public words, the scope and the binding, the ingress
  order and the origins, the library's API; written into `proving.md` §8
  and `identity-and-authority.md` §5–§7.
- **Dep:** 7.0. **Estimate:** 1 week.

### 7.8a The pvm-internal re-pin (S)

- **What, one commit, right after 7.0 and before 7.14 touches a chip:**
  slice 6's carried items inside `pvm/proof` and the kernels' code, which
  move program ids and fixtures: item 13 (the witness digest from
  `statement_header_words`), item 16's unmasked half, the final
  verifier's and recair's pieces of items 17–25, item 18's rest
  (`array::from_fn` in `agent/tree`'s hash, `leaf_terms`' named offsets);
  the fixtures regenerated. The teammate's second drop (the kit's
  fixtures and pinned ids).
- **Gate:** the stale-fixture test re-pinned once; format 35's AIR,
  `H_FOLD` and the wraps' roots byte for byte; `repro-aarch64` equal.
- **Dep:** 7.0. **Estimate:** 1–1.5 weeks.

### 7.8b The agent-side items and `blobs.lock`

- **What, one commit:** the rest of the batch: `vos-anchor`'s and the
  statement service's pieces of items 17–25, items 3 (`TryFrom<u32>` for
  `AnchorCode`), 4's guest half, 26 (`SpaceGenesis::version`), 27 (the
  `ANCHORS` mode out of `final-verify.elf`), 28 (the strictness fix,
  `read_nat` shared), 33 (`FetchKind`), 64–67 and 69; slice 6's L2
  (`blobs.lock` over every guest blob, checked by `check-no-std`). 7.1–7.3
  and 7.11 change the agent image and the service's blob before it; no
  hash pins a blob until `blobs.lock`. The teammate's third drop.
- **Gate:** `blobs.lock` reproduced from a clean build; the vectors and
  fixtures unchanged by it.
- **Dep:** 7.3, 7.11. **Estimate:** 1–1.5 weeks.

### 7.9 The Poseidon2 host call and the credential actor (S)

- **What:** pin H's `0x402` in the runtime (`precompile.rs`, the refine
  host, the inner machines, the wire's price table) and the guest shim's
  software fallback; pin G's `vos-credentials` actor (enroll, revoke,
  `path`, the ring) as a library actor, as `identity-and-authority.md`
  §6 pins it (its rows, the ring's freshness rule, `invite` and `claim`);
  its price measured. No change to
  `node/host/src/roots` (so 7.3 and 7.9 do not meet).
- **Tests:** the tree equals a reference built from scratch over random
  enrollments and revocations, on VOS and on the JAM-only host; slots
  reused lowest first; a path verified by the reference; a word ≥ p
  trapping the live call.
- **Dep:** 7.7. **Estimate:** 1–1.5 weeks.

### 7.10 The credential AIR (S)

- **What:** pin I's circuits (auth, owner) on recair's `Context`; a
  `MaskedComponents` set of `p2` and `qm31` (after the test's `P2Only`);
  the Blake2s-M31 channel wired in `pcs.rs` (the fork's
  `Blake2sM31MerkleChannel`); format 42 with its count on its own masked
  shape, and 44's counted beside it (S29's alternative, registered only if
  7.12 picks it); the prover and `verify_masked` over it; the
  membership-and-payment circuit (pin I, S37), measured only.
- **Gates:** soundness (a wrong path, a nullifier of another secret, an
  owner digest of another secret, a changed binding, each refused) and
  the forgery gates (a prover that skips the path's bits or the leaf's
  tag); a one-component masked set refused; leakage 2, 3 and 5 at N = 500
  in `test-proof` (2,000 at the slice's end); on x86 auth and the
  membership-and-payment circuit at most 60 ms and owner at most 30 ms on
  4 threads [est from the masked floor: 2^11 rows × about 400 columns].
- **Dep:** 7.7, 7.9 (the tree's hashes). **Estimate:** 3–4 weeks.

### 7.10b The node API and the gateway (S)

- **What** [decided, S41, S46, S49, S50]: the node keeps one binary API,
  and everything in front of it moves to a gateway.
  - **First, the grammar,** in the step's brief, which Fable reads before
    any code: a frame is a `u32` little-endian length of what follows, a
    `u16` request kind, over the socket a `u64` request id, then the
    kind's SCALE body; an answer frame repeats the header (the request's
    kind, and its id over the socket) before the answer's SCALE body. A
    frame the node cannot take is answered by the frame error, kind
    `0xffff`, its body a `FrameError` (`Oversize { limit }`,
    `UnknownKind`, `Truncated`, `NotRelayed`), and the stream (QUIC) or
    the connection (the socket) is closed. **The kind table** comes with
    it: each kind's number, body, answer and size limit, checked from the
    length and the kind before decoding (today's limit per route; an
    install's larger; 7.11's credentialed call's 1.5 MiB plus
    `cap::REQUEST` plus 4 KiB; `Time`'s and the node key's empty)
    [proposed widths].
  - **The node API:** every route of `node/host/src/ingress.rs` becomes a
    kind (the node's key, an agent's info and status, calls, queries,
    workflows, a schema, stats, agent and representative creation,
    installs, replicas, roles, reports), with today's answers. Two
    transports: a **unix socket** for a co-located gateway (its file mode
    the access), and **QUIC with mutual TLS** on `node/net`'s stack (raw
    ed25519 keys, an ALPN of its own, `vos-api/1`) for a remote one, the
    node accepting the gateway keys its config lists. Over QUIC one stream
    a request; over the socket, frames carry a request id and are answered
    out of order.
  - **Operator requests** [decided, S46]: the operator kinds (agent and
    representative creation, installs, replicas, roles, reports) are each
    signed by an operator key the node's config lists, with a nonce and an
    expiry as a call's, instead of the bearer token in an HTTP header; the
    node keeps each nonce until its expiry, so a gateway that relays one
    keeps nothing it can replay (`identity-and-authority.md` §6). Until
    they are built, the node accepts operator kinds on its unix socket
    only and refuses them over QUIC.
  - **The gateway,** `vos-gateway`, a binary of its own: today's HTTP
    routes, byte for byte (paths, bodies, statuses), translated onto the
    node API; the public TLS (`node/host/src/tls.rs`'s, moved); limits per
    address before authentication; leader-aware balancing across a
    space's nodes (it follows `NotLeader` and `Elsewhere`, as the client
    does now); 7.13's s4 screens on its SSH port. s4's operator console,
    when one is built, lives in it and only relays: the operator signs in
    their own client, never in the gateway (none is built here).
  - **The `vos-api` subsystem** [decided, S49]: the gateway's SSH port
    also serves an SSH subsystem, `vos-api`, under any key (a fresh
    ephemeral one, as no one in particular): a channel of node-API frames
    that relays the read-only kinds only (queries, among them the
    credential actor's `path` and `root()`, and `Time`), every other kind
    answered `NotRelayed` by the gateway, never sent to the node. 7.13's
    client fetches its paths and the node's time over it.
  - **The s4 app's client key:** the gateway's s4 app holds one ordinary
    VOS client key, with which it sends the claims (`claim(member)`, the
    ledger's `claim_row`) of members who have no key of their own; its
    authority is the registrar's invitations, which name the digests. It
    holds no credential bytes: the facility builds them.
  - **The gateway holds no authority:** the node verifies every
    signature and proof and runs every ingress check, whoever relays the
    frame. A compromised gateway can drop, delay or reorder requests and
    reads what it relays; it can forge nothing.
  - **The client's seam** is `node/host/src/client/http.rs`: a node-API
    transport beside it, used by `vosx`, the tests and `vos-scale`'s
    drivers (which measure the node; the gateway's cost is a row of its
    own); HTTP through a gateway stays for clients that want it.
  - **The node's HTTP is deleted** (`node/host/src/{ingress,http,tls}.rs`)
    once the gateway carries every route, the HTTP tests pass through it,
    and 7.6's final scale run is done, or T1 is re-measured over the
    node-API transport and both recorded [decided, S50].
- **Tests:** every route through the gateway answers as the node's HTTP
  did (a differential test while both exist); each kind's size refused
  before decoding, an unknown kind and a truncated frame, each with its
  frame error; a QUIC peer with an unlisted key refused at the handshake;
  a gateway that alters a signed call refused `BadSignature` by the node;
  an operator kind over QUIC refused while operator requests are
  socket-only; then an operator request unsigned, by an unlisted key,
  replayed or expired, each refused; a kind other than a query or `Time`
  over `vos-api` answered `NotRelayed` and never reaching the node; the
  gateway following `NotLeader`; the end-to-end suites through the
  gateway.
- **Dep:** 7.7 [decided, S50]: it needs nothing of the credential AIR and
  runs beside 7.9 and 7.10; 7.3 and 7.5, the last to change
  `node/host/src/{ingress,http,tls,client/http}.rs`, are merged.
  **Estimate:** 2–3 weeks.

### 7.11 The verifier at ingress (S)

- **What:** pin I's request, checks, apply rule and origins in the node
  API (7.10b) and `calls.rs`; the gateway's `POST /agents/{id}/credentialed`
  and `GET /time` as translations; the origin ABI's `Anonymous` and
  `Owner` kinds and the session-less input kind
  (`identity-and-authority.md` §15 step 0); the guards, with `once`
  (S43) and its system rows; the replicated binding set; the frame's
  per-format size caps; the `Time` request; the schema's `credential`
  field and the `credentials` system row (`Failure::Credentials`); the
  ledger test actor below, the demo's ledger in 7.13; the fuzz targets;
  `node/SECURITY.md` opened (the path leak, the handle copy, what
  operators and gateways learn). Its ABI change lands before 7.8b, so no
  pinned blob moves twice.
- **The ledger:** rows keyed by a name (1–32 bytes of UTF-8, which the
  client's chrome shows verbatim), each `(owner, balance, frozen)`,
  `owner` an owner digest. `invite_row(name, owner, expires_ms)` under the
  role `operator`, and `claim_row(name, owner)`, any caller, before the
  expiry: the credential actor's two steps, the invitation naming the
  digest. `mint(name, amount)` under `operator`. `transfer(from, to,
  amount)` under `Owner`: the handler debits `from` only if its live
  owner is the proof's digest and it is not frozen, and credits `to`,
  which must exist. `balance(name)`, a query, any caller. `rekey(name,
  owner)` and `freeze(name)` under `operator` [decided, S37]: `rekey` sets
  the row's owner digest, its name and balance kept, and lifts a freeze
  (a lost secret's recovery, after the member enrolls again); `freeze`
  refuses the row's debits until a `rekey`. Custodial by design
  (`identity-and-authority.md` §7).
- **Tests:** each check's refusal in order; a proof replayed at another
  node, refused at apply; an expired binding at apply by batch time; a
  root the replica has not applied (retryable); a revoked member's proof
  against the pre-revocation root refused once `ROOT_MAX_AGE` has passed
  by batch time; a proof of one call sent with another; two agents'
  scopes distinct; two spaces sharing a handle: one secret, one guard
  name, distinct nullifiers; a `once` guard: a second call of one
  nullifier refused, at ingress and, raced past it at another replica, at
  apply, while another scope's guard admits it; a `once` handler that
  fails or refuses leaves its nullifier free (a second proof of it
  admitted), while the first call's `b` sent again is refused `Replayed`
  [decided, S47]; a 1.4 MiB format-43 body
  within the frame's size (refused `Format` until 7.20 admits 43), a
  600 KiB credential proof refused `Size`; a wrong-PoW proof refused in
  under 1 ms; the origin logged, the proof not; a pay proof refused once
  the row's owner changed, and on a frozen row; a rekeyed row paying to
  the new owner's proof; a `claim_row` of a digest the invitation does
  not name refused; a transfer to a row that does not exist refused, its
  payer's balance unchanged.
- **Gate:** pin I's gates; **the executors' bound** [decided, S44]: at
  `k` verifying threads, for `k` = 1, 2, 4 up to the host's `N`, at least
  `100·k` credentialed calls a second, p99 within 50 ms of a signed
  call's; `N` and the host recorded. No absolute rate is claimed.
- **Dep:** 7.10, 7.10b (whichever ends last). **Estimate:** 2.5–3.5
  weeks.

### 7.12 The device library and the credential phone gate

- **What:** pins K and L for M4 (`prove_auth`, `prove_owner`, the
  derivation, `PathKeeper`), the Android build, and the phone bench
  (`tools/phone`, both builds). Paths refreshed apart from proofs
  [decided, S38]; `node/SECURITY.md`'s path entry states the leak as
  reduced: operators learn that a member digest is online, and its
  address, not when it proves; `vos-device`'s `SECURITY.md` states
  containment. `Threads::Auto` a plain even split until 7.17.
- **Phone gate PG1** (Fairphone 6): auth masked at most **250 ms** (target
  150 ms), the membership-and-payment proof at most 250 ms (S37), and
  owner at most 150 ms, each within 256 MiB, the 95th percentile
  recorded; verified on the phone and on x86; the seeded build's bytes
  equal to x86's.
- **Phone session:** P2. **Dep:** 7.10. **Estimate:** 1.5–2.5 weeks.

### 7.13 The demo in s4

- **Where** [decided, S40]: s4 (`~/src/virto/s4`), the owner's semantic UI
  over SSH, now ours to change as the demo needs: its Android client (a
  Rust `cdylib` with small Java bridges) and a server app in the gateway
  (7.10b). The node knows nothing of SSH or s4: the gateway speaks the
  node API to it.
- **The screens:** an s4 app (`s4_server::rui::App`) the gateway serves on
  its SSH port, three server-owned documents: *Enroll*, *Sign in*, *Pay*.
- **The facility `vos.credential`:** a client facility, called by the
  server and gated by the client's grant (a sensitive one, for the
  session by default), implemented in the client's Rust over 7.12's
  `vos-device`. Its operations: `enroll` (the handle, the space, the
  agents it names with their identities, and the methods it may prove
  for: the guarded methods' ids and scope names and the ledger's
  `transfer`; answers `member(s)` and `owner(s)`), `sign_in` (a call of a
  pinned method and its guard's scope name; answers the `Credentialed`
  body), `pay` (a prefill: the payer's row, the payee's row and the
  amount; answers the `Credentialed` body). The gateway forwards a body
  to the node as is; it builds no credential bytes. The facility needs
  Android 11 (API 30, pin K's Keystore key) and reports itself
  unsupported below it; s4 runs from API 23.
- **The secret sources** (pin K): s4's new `KeystoreBridge` (Java: the
  HMAC key's creation and use under `BiometricPrompt`, the `byte[]` handed
  to Rust and zero-filled) and YubiKit's CTAP2 `hmac-secret`, beside the
  YubiKit s4 already uses for SSH security keys. The client stores the
  source's reference and the pinned handle, agents and methods, nothing
  else.
- **An anonymous transport:** the gateway's credential surface accepts
  an ephemeral SSH key, drawn per connection, as no one in particular;
  authority comes from the proofs and the operator's invitation alone.
  The client keeps no resume token and remembers no grant for it, and
  pins the gateway's host key as for any host.
- **Paths and time** [decided, S49]: the facility opens a second SSH
  connection to the gateway, under a fresh ephemeral key, and the
  `vos-api` subsystem on it (7.10b); over it, it fetches its path when
  `root()` moves and on a timer (S38), never in the session that proves
  and never just before a proof, and reads `Time` before it picks an
  expiry. The library's `path_query`, `root_query` and `time_request`
  build the frames.
- **Trusted confirmation** [decided, S48]: before an owner proof the
  facility shows its own form in trusted chrome, the payer's row, the
  payee's row name and the amount, pre-filled from the server's `pay`
  request and editable; it encodes `transfer(from, to, amount)` from
  what the user confirmed, so what the binding covers is what the
  member saw, whatever the server's document says. Before an auth proof
  the chrome names the method and, for a `once` guard, that the call
  spends the member's one admission in its scope, so a server cannot
  pass a vote off as a sign-in. The facility's grant (per session, at
  `ServerHello`) and a call's confirmation (per call) are two prompts;
  the grant never stands in for the confirmation. The handle, the agents
  and the methods are shown and pinned in chrome at enrollment; a later
  request naming another space, agent or method is refused.
- **Claims:** a member here has no VOS client key, so the gateway's s4
  app sends `claim(member)` and the ledger's `claim_row` under its own
  client key (7.10b), its authority the operator's invitations, which
  name the digests.
- **The flows:** *Enroll* (the handle, agents and methods shown and
  pinned; the source's key created; `s` derived; `member(s)` and
  `owner(s)` claimed under an operator's invitation naming those two
  digests, so an interceptor cannot enroll its own); *Sign in* (the
  method and its guard shown in chrome, the user's consent at the
  source, auth proved on the path held, the call sent, its answer and
  the proving time shown); *Pay* (the server's form pre-filling the
  facility's; the payee and the amount confirmed or edited in chrome;
  the owner proof; the transfer sent; the balance shown).
- **Reach:** the phone reaches the development machine's gateway by
  `adb reverse` of the gateway's SSH port, which carries both the s4
  session and the `vos-api` connections; the gateway reaches the node by
  its unix socket.
- **What s4 changes:** its facility registry admits a facility of an
  external namespace (`vos.`) that a client build registers, as widget
  extensions are admitted now (today's rows are `s4.` only); `s4-server`
  gains an anonymous authenticator policy (any key, an identity for the
  connection only, no resume and no remembered grants across
  connections); the client gains a per-connection key for the credential
  surface (no saved token, no remembered grant, the host-key pin kept)
  and an SSH subsystem client for `vos-api`; a facility shows its own
  trusted-chrome form and asks a per-call confirmation apart from the
  session's grant, never with the document's text; the
  `KeystoreBridge`.
- **Not in scope:** recovery beyond revoking and enrolling again (and the
  ledger's `rekey`), several devices or a source that spans them, iOS,
  Credential Manager and passkeys, Play services and the Play Store, the
  desktop client's facility, a general method's confirmation from its
  schema, UI beyond the three screens, storing anything but the source's
  reference and what enrollment pinned (the handle, the agents, the
  methods).
- **Gate PG3:** the three flows end to end on the Fairphone 6 against a
  local space through the gateway, recorded (a screen capture, the
  gateway's and the node's logs); phone session P3.
- **Dep:** 7.0b, 7.10b, 7.11, 7.12. **Estimate:** 2–3 weeks.

### M4 acceptance

- **Gates:** `ci-full`, the checker loop, PG1, PG3.
- **Recorded:** the credential AIR's rows, proof bytes, proving on x86 and
  the phone, verify at ingress; `0x402`'s price; the re-pinned constants;
  a call's cost through the gateway beside the node API's.
- **Reviews:** Fable on 7.8a–7.11 (the re-pins, the actor and its host
  call, the AIR and its masking, the node API and the gateway, the
  ingress); then a push.

## M5: the device profile

### M5's outlook

**The gate (S3, ≤ 1 s on the Fairphone 6) is at real risk.** The
projection [est, from slice 5's cells and the phone's floor; 7.0a
corrects it]:

| | factor | time | basis |
|---|---|---|---|
| the floor, 8 threads, blowup 4, unmasked, the stale AIR | | 2.2 s | [measured] |
| lever 1: the statement over a Poseidon2 tree, BLAKE2B's 12.2M of 34.1M cells gone | ×0.64 | 1.41 s | [measured cells] |
| masking (c): every column at twice its rows | ×2.0–2.9 | 2.8–4.1 s | the wrap's ×2.6–2.9 [measured]; ×2.0 the doubled domain alone |
| blowup 2, if its proof fits 1.5 MiB (7.0a) | ×0.8 | **2.25–3.3 s** | [measured, slice 5] |
| lever 2: threads by core class, the preprocessed commitment at install | ×0.9 | 2.0–2.95 s | [measured: 4 threads vs 8; 2–9%] |
| lever 3: a lean kernel (the path walked in place, no copy; CPU, registers and memory are 88% of what remains) | ×0.55–0.7 | 1.1–2.1 s | [model, slice 5; the masked floor bounds it] |
| lever 6: the CPU split by opcode family (the CPU about half of what remains) | ×0.65–0.75 | 0.72–1.55 s | [model] |
| lever 5: word-level memory | ×0.88–0.92 | 0.65–1.4 s | [model] |
| the PoW 20 grind, which the factors above do not shrink (the floor's 2.2 s holds about 0.1 s of it) | +0.1 s, +0.3 s at the 95th percentile | **0.7–1.5 s** | [est, `device-params.md` finding 5]; PoW 16 with 47 queries (S29's lever, for 43 too) makes it about 6 ms |

So 1 s is reached only at the favourable end, after levers 1–3 and the
CPU split; the unfavourable end stays near 1.5 s with every lever.
The plan therefore **expects the CPU split** (7.18) and keeps word-level
memory next (7.19); the owner decides whether the gate stands after 7.0a's
masked proxy [decided, S20], and the plan aims at 1 s until then.

**One chip set, two formats** [decided, S23, S32]: the Poseidon2 chip,
the CPU split and word-level memory are built once, as chips the device
format 43 and the node's segment format 41 share; the device shape drops
the page boundary, the node's keeps it. A kernel leaf's `p2` rows grow
with the segment's width times its queries (59,300 of 2^16 at 40 queries
over 8,009 columns: about 760 columns to spare), and the split widens the
shape while it shrinks the cells; so **7.18's first day counts the
node's kernel leaves** over the proposed family layout. If any leaf would
pass 2^16 with the split, the split stays device-only and format 41 takes
the Poseidon2 chip alone, or nothing if that too overflows; no fold-shape
change in this slice. The nodes prove under 35 until 7.21.

### 7.14 Masking the segment chips (S)

- **What:** `MaskedComponents` over the segment AIR's `BuiltInComponent`s:
  the active-chip mask in `draw_relations`, a finalize hook for the 14
  chips that finalize unpaired, a per-component `h` from its offsets, the
  fixed tables' multiplicity columns padded to the floor; the degree audit
  (5,177 constraints at ≤ 3 under (c), slice 6's R5) on the built set.
- **Gates:** soundness 1–10 and leakage 1–7 (slice 6's 6.6) on a masked
  segment of a small kernel; R1 on every column class; **format 35's
  proofs byte for byte** (the shared segment prover unchanged for nodes
  until 7.21).
- **Dep:** 7.0a, 7.8a. **Estimate:** 4–6 weeks.

### 7.15 The device shape and its Poseidon2 chip (S)

- **What:** pin J's boundary-free shape (the data table, the first-touch
  rules, the permission table, the io-hash output); pin H's chip in the
  shared chip set (format 41's, not yet admitted, and 43's); the device
  program id, derivation at install.
- **Forgery gates:** a first touch of a data byte other than the table's,
  a nonzero first touch of stack or heap, a touch outside the regions, a
  write to a read-only page, a second segment; a Poseidon2 output not the
  permutation's, an input word ≥ p (p included), a call without its row:
  each refused.
- **Dep:** 7.14, 7.9 (the call). **Estimate:** 3.5–5.5 weeks.

### 7.16 The device parameters, measured

- **What:** the auth statement over the Poseidon2 tree (S21; the BLAKE2b
  one measured beside it) under the device shape,
  masked, at the candidates (blowup 2 with 86–87 queries, blowup 4 with 43
  at PoW 20 or 47 at PoW 16, blowup 8 with 29; the Blake2s-M31 channel,
  Blake2b-256 for comparison) on x86, then on the phone; format 43 pinned
  at the fastest candidate within pin J's memory and size budgets, by its
  median and its 95th percentile. Phone session P4.
- **Dep:** 7.15. **Estimate:** 1–1.5 weeks.

### 7.17 Levers 1–4

Each measured on x86 as it lands (scaled by the ARM factor), all four
together on the phone in session P5.
1. **The statement over the credential actor's Poseidon2 tree** through
   the chip (S21): BLAKE2b and the AND table leave the shape.
2. **Threads by core class** (`Threads::Auto`: the A720s and A520s given
   work by their measured rate, not rayon's even split), and the
   preprocessed commitment computed once at install.
3. **A lean kernel:** no argument copy, the path walked in place.
4. **Parameters again:** per-component `h`, blowup, queries and PoW
   re-chosen on the lighter shape.
- **Estimate:** 1.5–2 weeks.

### 7.18 The CPU split by opcode family (expected)

- **First day, the count** [decided, S32]: the node's kernel leaves
  counted over the proposed family layout and the chip (`count-35.log`'s
  method), before the design is fixed. Any leaf past 2^16 `p2` rows at 40
  queries: the split is device-only, and 7.21 takes the chip alone, or
  nothing; no fold-shape change.
- **What:** the shared chip set's CPU split into components per opcode
  family (ALU, memory, control, host calls), each with only its columns,
  so a row pays for its family alone (−50–70% of the CPU's cells [model,
  `proving.md` §9]); for format 43, and for 41 if the count allows; its
  forgery gates per family, on a device shape and, if for 41, on a node
  segment with the boundary.
- **Exit:** PG2 passes twice, a day apart (sessions P7 and P8; P6 mid-way),
  or the owner decides between 7.19 and the measured time (S20).
- **Dep:** 7.17. **Estimate:** 8–12 weeks for both shapes, 6–10 for the
  device alone.

### 7.19 Word-level memory (if PG2 still misses)

- **What:** the shared chip set's memory argument at word granularity:
  4–8× fewer MEMORY rows [model]; forgery gates for sub-word access; for
  41 only under S32's count, the page boundary's binding re-derived then.
- **Dep:** 7.18 and the owner's call. **Estimate:** 4–6 weeks.

### 7.20 The device kernel at ingress, and PG2

- **What:** `prove_kernel` (pin L); pin J's ingress path (a device proof
  authorizing as an auth credential does); the demo's *Sign in* given a
  choice of the general zkVM's auth kernel beside the credential AIR.
- **Phone gate PG2** (Fairphone 6): the auth statement under the device
  profile, masked, **at most 1.0 s** (the median of three rounds' medians,
  the 95th percentile recorded), peak resident at most 1 GiB, proof at
  most 1.5 MiB; verified on the phone and accepted at a space's ingress.
- **Tests:** two witnesses of different path shapes proved under one
  device program id (pin J's witness-independent trace); a run past the
  program id's log sizes refused by the prover.
- **Dep:** 7.11, 7.18 (or 7.19). **Estimate:** 1–2 weeks.

### 7.21 The second re-pin: the node's segment format 41 (S)

- **What, one commit** [decided, S23, S32]: format 41 admitted with what
  7.18's count let in (the chip and the levers, or the chip alone; if
  nothing fits, no format 41, and the step records the counts); the page
  boundary kept; the node's default prover on 41; 35 retired;
  `SEGMENT_CHIPS` and the install record's `Shape` re-encoded; `derive`
  admitting `0x402` in node kernels. It re-pins every program id and leaf
  circuit, the agent image, the kernels, `final-verify.elf`,
  `final-verify-test.elf`, the Wasm blobs, the statement service's blob,
  `blobs.lock` and the reproducibility constants; the teammate's fourth
  drop (fixtures and pinned ids, no code).
- **Recounted** (the Fable review's M9): 41's parameters on its own
  reference shape, moved if 40 queries and PoW 24 count under 62 proven
  bits; the kernel leaves counted again as built, within 2^16 `p2` rows;
  `H_FOLD` and the wraps' roots byte for byte.
- **Gates:** the fixtures regenerated through the seeded seam; `test-proof`
  (segments, leaves, folds, the masked wrap per statement); the leakage
  gates at medium N; the shared chips' forgery gates on node shapes; the
  reproducibility gate on x86 and aarch64; `just e2e-chain`; the
  throughput test's window statement against slice 6's 46.5 s (a
  regression past 10% is fixed or recorded with its cause).
- **Dep:** 7.18 (and 7.19, if built). Beside 7.20. **Estimate:** 2.5–4
  weeks (1 if nothing enters 41).

### M5 acceptance

- **Gates:** `ci-full`, the checker loop, PG2 (or the owner's call on the
  measured time), 7.21's gates.
- **Recorded:** the device shape's rows by chip, each lever's effect on
  the phone, the proof's bytes, verify at ingress; format 41's rows, leaf
  counts and proving time against 35's.
- **Reviews:** Fable on 7.14, 7.15, 7.18 (and 7.19), 7.21 and the
  parameters; then a push.

## The slice's end

### 7.22 The carrier audit, extended

- **What:** slice 6's R7 audit over the new carriers (the credentialed
  call and its log entry, the `path` query, the library's errors, the
  node API's frames, the gateway's logs, s4's `KeystoreBridge` and
  facility, the phone bench); slice 6's M6 (more needles, a
  run over small values).
- **Dep:** 7.11, 7.20. **Estimate:** 1 week.

### 7.23 Acceptance, the quality review and the carried rest

- **Gates:** `slice-gate`, the checker loop, `just e2e-chain`, the kit's
  sync check, the scale test's run 3 again on the final build, PG1, PG2
  and PG3 on the final build.
- **The carried rest** (behaviour-preserving commits, proof bytes
  unchanged): slice 6's M5(d) (the release binary scanned), M5 (fault text
  out of logs and answers), L1 (a seeded-hash pin of the small masked
  circuit in `check`), L8's `ABOUT` string, L9's rest (`tamper` under
  `seeded-masks`, `ProveError`'s values, a `stwo=warn` default,
  `check-no-faults` in `check`), items 14, 30, 31, 35, 50, 70 and 77; the
  six owner's-call items (S31).
- **Reviews:** the Opus code-quality review, then the slice-end Fable
  review, each folded. **Docs:** `proving.md` draft 7, `core-model.md`,
  `identity-and-authority.md`, "Slice 7 accepted".
- **Estimate:** 3–4 weeks.

## Where the carried items land

| carried from slice 6 | where |
|---|---|
| the slice-7 re-pin batch: its pvm-internal items (13, 16's unmasked half, the final verifier's and recair's pieces of 17–25, item 18's rest) | 7.8a |
| the rest of the batch (`vos-anchor`'s and the service's pieces of 17–25, items 3, 4, 26–28, 33, 64–67, 69) and L2's `blobs.lock` | 7.8b |
| F2, F3, L4, item 74, item 29, the info items (duplicate founding keys, the service's lenient read) | 7.1 |
| `migrate_digest`'s nonce; L3's one-way migration | 7.1 (gone with C1) |
| L5 (jam-dev's `push`), the untested once-a-window recheck | 7.2 (gone with C3) |
| L4 of M3b/M3c (no production prover for rootless statements) | 7.1 (by design with C7) |
| M3, M4, L6 (a)–(f): the worker's edges; item 68 (quarantined, S30) | 7.3 |
| the representative's load lever (6.19's ops note) | 7.3 (C10, C11) |
| items 53, 58's performance half; L8 and the clock and catch-up ops notes | 7.6 |
| L3 (`default-members`, the release build gated) | 7.4 |
| M6, the audit's needles | 7.22 |
| M5(d), M5, L1, L8's rest, L9's rest, items 14, 30, 31, 35, 50, 70, 77 | 7.23 |
| the owner's-call items 1, 5, 34, 46, 54, 58 | 7.23 (S31) |
| 5.6's phone run | done (2026-10-25); 7.0a repeats it on today's AIR |
| one founding key registers the space anywhere (pin D's known limit) | carried: its lever adds a rule |
| the representative's clock guard (a quorum of follower clocks) | carried unless the scale runs show the skew binding |
| M6(d)'s FRAME-agnostic runner; M6(e)'s code with the port; M3b's deferred Kreivo gates 1–5 | carried: the teammate's pallet and the port, after the slices |
| the prover-time levers (ALU padding, WITNESS_INPUT in the entry class, a leaf over small segments) | carried: node proving is not this slice's |
| the Blake2b hook (decision 4); `getrandom`'s failure (inherent, documented) | carried |
| the per-call identity read at ingress (the scale test's unmodeled hot path, the Fable review's L9) | carried to the identity agent's slice, for its scale run |
| C-DJUMP, the ledgers' 2^27 gap, the BLAKE2b pointer near 2^32, refine slices' page permissions | the audit's scope |
| the external audit | after slice 6, before value; its scope gains the credential AIR, the device shape, its Poseidon2 chip and their masking |
| the heavy cleanup before master | carried |

## Risks, and the gate that retires each

| risk | gate | when |
|---|---|---|
| **likely:** the device profile misses 1 s on the Fairphone 6 (M5's outlook: 0.7–1.5 s with every lever) | 7.0a's masked proxy on today's AIR first; the owner's call on the gate then (S20); 7.17–7.19 in order, on x86 between phone sessions | 7.0a, 7.17–7.19 |
| the owner's one phone delays the critical path (about nine sessions) | sessions batched and asked a week ahead (S33); x86 and qemu-aarch64 proxies between them | every PG |
| masking the segment chips costs more than the wrap's factor (the 2^12 floor, padded tables, 14 unpaired chips), or its proofs are too big to send | 7.0a's proxy and bytes; 7.14's gates; per-component `h`; blowup 4 halves the floor and the bytes; pin J's 1.5 MiB | 7.0a, 7.14, 7.16 |
| a device format under its margin (37 counts 61.86 under (c)) | formats 42 and 43 counted on their masked shapes, pinned by tests | 7.10, 7.16 |
| 7.14 breaks the nodes' segment proofs (it edits the shared prover) | format 35's proofs byte for byte | 7.14 |
| the gate device's Keystore refuses a per-use HMAC key (no StrongBox, or the prompt refusing a `Mac`) | 7.0b's probe; the TEE-backed key, recorded; a security key's `hmac-secret` through YubiKit | 7.0b |
| a lost key (a factory reset, the screen lock removed, a lost security key) loses `s` and the member's funds | revoke and enroll again; the ledger's `rekey` moves the rows (S37) | 7.11, 7.13 |
| a revoked member, or a thief of `s`, keeps paying | the ledger's `rekey` and `freeze` under an operator role (S37) | 7.11 |
| a gateway forges, alters or replays requests | the node verifies every signature and proof and runs every check; operator requests signed, not bearer tokens, and socket-only until built (S46); the s4 console signs in the operator's client; a test of an altered call | 7.10b |
| moving the node's HTTP to a gateway changes an answer | a differential test of every route while both exist; the end-to-end suites through the gateway before the node's HTTP is deleted | 7.10b |
| deleting the node's HTTP leaves 7.6's T1 measured on a transport that no longer exists | the deletion after 7.6's final run, or T1 re-measured over the node API and both recorded (S50) | 7.6, 7.10b |
| a hostile gateway's document makes the member confirm another payment, or spend a `once` admission as a sign-in | the facility's own chrome form for the payee and the amount, the server's request a prefill only, the arguments encoded from what the user confirmed (S48); the method and its `once` guard named in chrome; the agents and methods pinned at enrollment, others refused | 7.13 |
| a `once` admission spent by a call the handler refused | the `once` row written only on `Ok`, in the same apply (S47); a test | 7.11 |
| a single-component masked set leaks its claimed sum | two components at least (pin I), a test that a one-component set is refused | 7.10 |
| a credential proof replayed at another node, or across agents or spaces | the binding names the space, agent, method and program; recorded at apply; scopes namespaced by space and agent | 7.11 |
| two spaces sharing a handle link their members | the scope carries the `SpaceId`; the app shows and pins the handle; stated in `node/SECURITY.md` | 7.11 |
| a revoked member proves against an old root | ring roots older than `ROOT_MAX_AGE` refused | 7.11 |
| ingress becomes a verification DoS target | per-format size caps first, the PoW before any decommitment, a bound per connection and an executor budget, no shared bucket; fuzzing at ingress | 7.11 |
| a device proof's shape leaks its witness | the trace padded to the program id's log sizes; branch-free kernels; a test with two path shapes | 7.20 |
| path fetches reveal which member proves | paths refreshed apart from proofs on a connection of their own, the `vos-api` subsystem under a fresh key (S38, S49); the address still links, and each tree change shows the online members, stated in pin G and `node/SECURITY.md`; syncing the tree is the later fix | 7.12, 7.13 |
| a re-pin breaks the kit, the vectors or the teammate's vendored tree, or parallel steps collide in `pvm/proof` | the batch split (7.8a before 7.14, 7.8b after 7.3 and 7.11); `blobs.lock`; the vectors regenerated once in 7.1; four drops announced in `teammate-note.md` | 7.1, 7.8a, 7.8b, 7.21 |
| simplifying pin D changes a design the teammate is building | the teammate told now (S19); one regeneration of `spaces-pallet.md` and the vectors | 7.0, 7.1 |
| a stolen key ends a space for good (accepted, S11) | the tombstone; the deposit released and `dispatch_as_sovereign` callable on an ended space; the runbook re-seeds the tree from the old `member` digests | 7.1 |
| an apply bug or a cloned store ends a space through the honest node's evidence | the divergence guard; signing only applied rows; a restored backup treated as a compromised key | 7.2 |
| `Unlisted` handoffs loop | one handoff a window a leadership; no handoff when no replica is listed | 7.2 |
| format 41's wider segment AIR overflows a kernel leaf's 2^16 `p2` rows | 7.18's first-day count; the split device-only, the chip alone or nothing in 41; no fold-shape change (S32) | 7.18, 7.21 |
| the CPU split or word-level memory, shared with the node, slows node proving or opens a forgery on node shapes | the forgery gates on node segments with the boundary; the throughput test against slice 6's 46.5 s | 7.18, 7.21 |
| per-replica memory, idle timers or the single runtime thread cap agents per node | 7.6's run 1 first; quiescing idle groups the named lever | 7.6 |
| **T1 at risk:** a node cannot commit 5,000 calls a second at a 50 ms p99. One FIFO executor queue takes all work (signature checks, refine and dry run as two hops, accumulates, queries, root builds); the single `vos-node` runtime thread also reads the store synchronously each batch; a group has one batch in flight (commit p50 41–49 ms plus apply 25–29 ms in 7.5's runs) | 7.6's first run measures the queues (`refine_queue`, `dry_run_queue`, `root_build_queue`); the levers in order: refine and dry run in one executor job, a priority lane for the batch path, batch signature verification, per-batch reads off the runtime thread, runtime threads sharded by group, batch pipelining | 7.6 |
| LAN clock skew fails reads or moves windows | `vos-scale check` refuses offsets above 100 ms; C9's fail rate measured | 7.4, 7.6 |
| the knee is a slow host's, a NIC's or a governor's, not the node's | `check` records disks, links and governors, refuses Wi-Fi; `report` names each host's binding resource; run 2 without the slowest host | 7.4, 7.6 |
| thermal throttling skews the phone numbers | the runbook's temperature and battery checks, rounds 60 s apart, the 95th percentile recorded | every PG |

## Estimates

| | weeks |
|---|---|
| 7.0, the docs and the probes | 1.5–2 |
| M3.9 simplification (7.1–7.3) | 6.5–9.5 |
| M3.9 scale (7.4–7.6) | 4.5–8 |
| M3.9 acceptance | 0.5 |
| M4 (7.7–7.13 with 7.8a, 7.8b and 7.10b, and acceptance) | 15.5–22 |
| M5 (7.14–7.18, 7.20, 7.21 and acceptance) | 22–33.5 |
| M5's word-level memory, if needed (7.19) | 4–6 |
| the slice's end (7.22–7.23) | 4–5 |
| **slice 7, engineer-weeks** | **about 55–81, up to 87** |

- **The critical path is M5's chain:** 7.0 → 7.8a (beside 7.0a) → 7.14 →
  7.15 → 7.16 → 7.17 → 7.18 → 7.21 → M5's acceptance → 7.22 → 7.23, about
  **27–39 weeks** of calendar with the groundwork beside M3.9 (S7), up to
  45 with 7.19, about 2–4 fewer if S32 keeps the split device-only; each
  phone session within a week of its ask (S33). 7.20 runs beside 7.21.
- **The second re-pin costs 1–4 weeks** on that path (S23, S32).
- **Beside it:** M3.9's two tracks (7.1 → 7.2 → 7.3 → 7.6, and 7.4 → 7.5
  → 7.6); M4's chain (7.7 → 7.9 → 7.10 → 7.11 → 7.13, with 7.10b beside
  7.9 and 7.10 and 7.11 after whichever of 7.10 and 7.10b ends last
  [decided, S50], 7.8b after 7.3 and 7.11, and 7.12 after 7.10), 9.5–13
  weeks of steps, about 11–14.5 with acceptance, done within M5's; 7.10b
  off the chain takes 2–3 weeks from it.
- **Against `proving.md` §11's 12–20 weeks for M4 and M5:** that row left
  out M3.9, the re-pin, the node API and its gateway, the ingress
  verifier, the demo, masking the segment chips (7.14) and the CPU split.

## Decisions

**Taken by the owner:** S1–S5 before the plan; S6–S31 on draft 2; S32
and S33 on draft 3; S34 on 7.2's review; S35 and S36 on the scale runs'
hardware and S52 on its wiring; S37–S44 on 7.7's questions and S46–S51
on Fable's review of 7.7 (`research/slice-7/owner-decisions.md`),
among them C1–C11 all taken and C4 fully terminal (S8–S18), the teammate
told now (S19), the chip and the levers in the node's format too as the
leaf count allows (S23, S32), a stable space handle (S25), the phone
sessions (S33), the demo in s4 (S40), the node's binary API and its
gateway (S41), the Keystore and security keys instead of passkeys (S42,
reversing S6), the `once` guard (S43), signed operator requests (S46),
the `once` row on `Ok` only (S47), the facility's own confirmation form
(S48), the `vos-api` subsystem (S49), 7.10b beside 7.9 and 7.10 (S50),
the input's tag (S51).
S7, S11 and S25 carry the review's amendments (7.8's split; the
divergence guard and the deposit released on `Ended`; the scope's
`SpaceId`, the re-seeding runbook and `member` without an epoch).

**Slice-6 decisions they reverse** (each named in `owner-decisions.md`):
decision 7 (rotation by S13, resume by S11), decision 8 (S9, S12),
decision 10 (S12), decision 18 (S11); `proving.md` §7's equivocation,
migration and "`S_w` over every agent's root" (S11, S9, S17);
`spaces-pallet.md` §13 questions 2 and 12, calls 5 and 6, vectors G5,
G14, G15 and G19, and G1 and G18 in part (`teammate-note.md`); slice 6's
signed `start_window` (S10) and re-cuts (S16).

**Settled by the evidence, the owner's to override:** device formats
counted on their masked shapes (30 and 37 retired unregistered, 42 and 43
new); the credential tree in the actor's own rows, `RootKind` untouched
(pin G); the credential AIR as a recair circuit over `p2` and `qm31` (pin
I).

## Open questions

Two, each closed by a measurement:
1. **S3's gate** (S20): after 7.0a's masked-cost proxy on today's AIR, the
   owner keeps ≤ 1 s or sets the gate from the measurement; until then the
   plan aims at 1 s.
2. **The credential parameters** (S29): 7.12's grind on the phone picks
   PoW 16 with 47 queries (format 44) if its 95th percentile passes 50 ms,
   else PoW 20 with 43 (format 42).

7.7's design round asked six more (7.7-Q1 to Q6, `slice-7-progress.md`,
7.7); the owner answered each: Q1 by S37, Q2 by S38, Q3 by S39, Q4 by
S42, Q5 by S43, Q6 by S44, folded into the pins and steps above. Fable's
review of 7.7 asked six (`research/slice-7/7.7-fable.md`, Q1 to Q6),
among them the operator requests S41's fold had left open; the owner
answered each by S46–S51, folded likewise.
