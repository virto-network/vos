# Federation showcase: three spaces, one settlement

Status: PLAN. The first public showcase of VOS: **bank A (a space) pays
bank B (another space), and the two banks settle on a third, parent space**
— every space running more than one node so CRDT/Raft replication is part
of the story. Companions: `bank-federation.md` (the wave model this
executes), `proving-time.md` (why proving is a separate beat), and the
Bloque business context (`bloque/bank-federation/docs/overview.md` — banks
keep private ledgers, the shared venue is the neutral referee).

The plan also carries the **production-readiness ergonomics tracks** the
showcase surfaced but does not block on: `vos::agent::AgentState`,
`#[provable]`, and full-fidelity `#[msg]` argument typing.

Sizing legend used throughout: **S** ≤ 1 day · **M** 2–4 days ·
**L** 1–2 weeks · **XL** multi-week, spike first.

## 0. Corrections to the premise

Recon corrected three assumptions; the plan is built on the corrected
picture.

1. **The hyperspace exists.** A manifest field `hyperspace = "name"` spawns
   a second space-registry replica at the well-known
   `ServiceId::HYPERSPACE_REGISTRY` (= 1) whose replication id derives from
   the name alone, so all member spaces' nodes converge on one shared CRDT
   registry (`vosx/src/commands/space/up.rs:200-217`,
   `vos/src/abi/service.rs:31-37`). Every local agent is advertised into it
   (`register_remote`), and `Context::resolve` falls through
   local → hyperspace, returning ServiceIds that route cross-node over
   libp2p (`vos/src/actors/context.rs:397-445`). Three e2e tests exercise
   it, including the two-bank federation e2e.
   **But it is a *namespace*, not a space** — no genesis, no membership, no
   agents of its own. "Settling **on** the hyperspace" therefore means: a
   **third ordinary space** (the venue) whose nodes also declare the same
   hyperspace name and run a settlement actor advertised into the shared
   registry.

2. **Refine is the only guest execution.** Guest `_start` is a pure refine
   pass with buffered effects; the host **commits by replaying the journal
   natively** — no second PVM invocation (the guest accumulate entry exists
   but the VOS runtime does not invoke it; the kernel is single-entry PC=0
   with φ[7] phase select, `vos/src/runtime.rs:7-21`). `#[provable]` does
   not introduce a stage split — and the correction *strengthens* it:
   refine is the only thing that executes in the guest, so it is the only
   thing that ever needs proving.

3. **The settlement venue does not exist — but its kernel does.** Today
   "settlement" is bank B's clerk-bridge bilaterally verifying A's voucher.
   Nothing accumulates obligations, no netting window exists, and no actor
   can receive a settlement claim on a third space. This is the largest
   net-new runtime code in the showcase — and smaller than it sounds:
   cipher-clerk ships a tested bilateral net-settlement kernel
   (`SettlementClaim` with signature + Pedersen net-flow commitment,
   `reconcile()` pairwise zero-sum via exact point negation,
   `reconcile_multi_peer()`, `to_bytes`/`from_bytes`;
   `cipher-clerk/src/settlement/mod.rs`), behind a `settlement` cargo
   feature currently enabled nowhere in vos. It compiles verify-only with
   `--no-default-features --features settlement`.

## 1. The demo script (target narrative)

Mirrors the Bloque story (`overview.md` §5–§8): private bank ledgers,
instant intra-bank payments, periodic net settlement on a neutral venue.

**Topology: 9 daemons (decided 2026-07-08).** `bank-a` ×3, `bank-b` ×3,
`venue` ×3, all declaring `hyperspace = "bank-federation"`. Three voters
per space because a 2-voter Raft group has quorum 2 and therefore **zero
fault tolerance** (any node down ⇒ no writes; a dead leader ⇒ frozen
ledger, no election possible); at ×3 everywhere, any single node —
including any leader — can be killed on stage and the space keeps
serving. The quorum arithmetic still goes in the runbook.

1. **Topology up.** 9 daemons; a live **watch view** (see S8) shows each
   space's members, each Raft group's leader, and the payments/settlement
   counters.
2. **Intra-bank instant payment** (the Bloque headline, `overview.md` §6):
   a bank-A user pays another bank-A user — ledger-only, instant, no venue
   and no other space involved.
3. **Replication beats.**
   - *Raft*: kill bank A's **leader** (identified live via `raft-status`);
     watch failover; run another intra-bank payment — the bank stays up.
     Restart the old leader; watch it catch up (state-root convergence).
   - *CRDT*: register a new agent at bank B and resolve its name from a
     **venue** node — the hyperspace registry converging leaderlessly
     across 9 nodes, explicitly contrasted with the Raft beat.
4. **Cross-bank payments**, both directions. Bank A debits its own
   Raft-replicated ledger, a signed voucher ships to bank B's clerk-bridge
   over the hyperspace; B verifies (signature + receiver-side state-root
   anchor) and credits its own ledger. The counter ticks: *payments this
   window: N*.
5. **Privacy beat** (`overview.md` §8's #1 gain): bank A attempts a direct
   read of bank B's ledger — refused (`ClientError::Forbidden`, already
   pinned in the e2e). Then show a submitted settlement claim's contents:
   Pedersen commitments only, never amounts — private from the venue and
   from the other bank.
6. **Settlement beat (the headline).** Issuance quiesces, the window
   closes; **each bank's own driver** (two independent processes, each
   holding only its own clerk key — see S3) derives its net-flow claim from
   its actor-recorded sums, signs it, and submits to the **venue actor on
   the third space**; the venue runs the pairwise zero-sum check (the two
   net-flow commitments must cancel), records the settled window, and the
   banks' voucher channels re-anchor. Counter: *N payments → 1 settlement*
   — the economics beat (`overview.md` §8: fees only on settlement).
7. **Proof beat (separate, honest).** A real conservation-of-value STARK —
   precomputed or kicked off async at demo start — ships cross-node via CAS
   and is verified through the streaming verifier on the receiving bank
   (seconds-scale, ~3 MiB/segment). The JAM-PVM `settle.elf` verify
   (~10.7M cycles) is shown as the **Wave-2 backstop machinery** — "this is
   what on-chain settlement verification will run" — never as "this
   settlement was proof-verified".

**Trust framing (said out loud, and written into the talk track):**

- Wave-1 = mutually-known operators; vouchers and claims are
  signature-trusted.
- The venue checks mutual **consistency** of the two banks' books, not
  solvency — solvency is exactly the Wave-2 proof slot.
- The venue space **stands in for the on-chain settlement venue** the
  Bloque docs promise (a public chain no single bank controls); Wave 2
  moves claim verification on-chain — `settle.elf` is that verifier. State
  who operates the venue in the demo and why it is neutral-enough for
  Wave 1.
- What makes the zero-sum beat more than theater at Wave-1 trust: the two
  claims are produced by **independent per-bank drivers** and each claim's
  net flow **must** include the receiving bridge's actor-recorded sum (S2)
  — so the check demonstrates two independently-kept books reconciling,
  at signature-level trust.

## 2. Where things land (repo layout)

The user-facing setup lives in **`bloque/bank-federation`** (already a
Rust crate); vos gains only generic, reusable pieces.

| Artifact | Home |
|---|---|
| `clerk-settle` venue actor | vos `actors/` (decided — generic clerk-family piece, alongside clerk-ledger/clerk-bridge, which **stays**: the bridge is the per-bank ingress whose anchor/dedup/window sums make settlement honest; clerk-settle is the venue end of the same wire) |
| clerk-bridge window/claim handlers, `anchor_reset` | vos `actors/clerk-bridge` |
| `vosx space raft-status`, dynamic-dispatch byte args, macro work | vos |
| 3-space multi-node e2e | vos `vos/tests/elf_integration.rs` |
| **Bank driver** (per-bank binary: voucher/claim signing, issuer accumulator) | bloque/bank-federation `src/` |
| Space manifests (bank-a, bank-b, venue) | bloque/bank-federation (vos's `examples/space-clerk-demo.toml` optionally updated to raft to close bank-federation.md item 1 in-repo) |
| Orchestration scripts (7-daemon bring-up, demo beats) | bloque/bank-federation |
| Demo runbook + talk track | bloque/bank-federation `docs/` |

The companion doc `vos-core-execution.md` is the **leading track**: fixing
VOS itself (refine/accumulate, the agent/sub-actor model, the provable
seam) comes first, with the showcase workstreams proceeding in parallel
worktrees where they don't touch the core (§7).

## 3. Gap map

| # | Gap | Track | Size |
|---|-----|-------|------|
| G1 | Settlement venue actor (`clerk-settle`) on the third space | S | M |
| G2 | Claim production: per-(peer, currency, window) net-flow sums on the bridge + window lifecycle handlers | S | M |
| G3 | **Per-bank driver tool** (signs vouchers/claims, keeps issuer accumulator, reads actor state) — *no existing component can do this; the cipher-clerk CLI settles against its own file ledger, not the actors* | S | M |
| G4 | Window close protocol: quiesce barrier, reconcile-failure diagnostics, post-settlement `anchor_reset` | S | M |
| G5 | Bank/venue manifests; clerk-ledger `consistency=raft` (plan item 1); bridge posture correction (Local, **not** Ephemeral) | S | S |
| G6 | Raft caller-identity gate: clerk-ledger **and clerk-settle** under leader-forward (Operator-gated mutators arrive as the forwarding node's peer — the chronos lesson) | S | M |
| G7 | 3-space multi-node in-process e2e (venue ×2 + bank-A ×2 minimum; bidirectional bridges) | S | L |
| G8 | 7-daemon orchestration: dial graph, enrollment, port table, health checks, ops hardening | S | M |
| G9 | Watch view (status table: raft-status × spaces, registry listings, counters) | S | M |
| G10 | `vosx space raft-status` (RaftStatusReq plumbing exists, no CLI) | S | S |
| G11 | Hyperspace membership not persisted (manifest-only; wrong restart flags detach the space) | S | S |
| G12 | Demo runbook + talk track (quorum math, trust framing, recovery procedures, Q&A traps) | S | S |
| G13 | Async prove job in the prover extension (prove can't run inside a live invoke) | P | M |
| G14 | Real-STARK cross-node beat never rehearsed on a real multi-node topology | P | S |
| G15 | Turnkey seg_steps re-pin tool (dial prove RAM to demo hardware) | P | M |
| G16 | `settle_run`/`settle_transpile` gating tests silently skip (stale `recursion-verifier` paths) | P | S |
| G17 | Streaming prover: design note now (integration sketch in §5.5), implementation later; SideNote diet first | P | XL |
| G18 | `vos::agent::AgentState` child-lifecycle library | E-B | L |
| G19 | Default agent actor (children as simple child actors) | E-B | L |
| G20 | Child teardown (uninstall → stop propagation; `remove_child`) | E-B | M |
| G21 | Status/Role derive macros; port messenger `clients.rs` to generated Refs | E-B | S+M |
| G22 | `#[provable]` public-input semantics design (the load-bearing decision) | E-C | S* |
| G23 | `#[provable]` macro + host `prove_call`/`verify_call` + purity guard | E-C | M |
| G24 | Guest build centralization (target spec, toolchain, cipher-clerk `.wt_alt` path dep) | E-C | M |
| G25 | Custom rkyv structs as `#[msg]` args (kill the `Vec<u8>`+manual-decode idiom) — **pull forward: lands before S1's handler surface freezes** | E-A | M |
| G26 | `[u8; N]` args/returns (ids, hashes, roots, pubkeys — ~25 call sites) | E-A | S |
| G27 | Return types in schema metadata (S/M); nested type descriptors + JSON↔rkyv for CLI/gateway (L) | E-A | S+L |
| G28 | Generated Ref reply decode uses `access_unchecked` on peer-supplied bytes | E-A | S |
| G29 | Dynamic dispatcher byte args (`space call` `@file` already works; this is polish, not a blocker) | E-A | S |
| G30 | Container/compose path (no ELFs in image, no `space join` in entrypoint, LTO hang) | later | L |
| G31 | Hyperspace trust surface (`register_remote` name hijack, unauth `register_peer`) | Wave-2 | — |

`S*` = small to write, load-bearing to get right.

## 4. Track S — the showcase spine

### S1. `clerk-settle`: the venue actor (G1)

New PVM actor `actors/clerk-settle`, pattern-matched on clerk-bridge:

- **State**: registered banks `(name, clerk_pubkey)`; submitted claims
  keyed `(pair, currency, window)`; settled-window log.
- **Handlers**: `register_bank` (Operator-gated); `submit_claim(claim,
  voucher_count, rk_set_hash)` — parse `SettlementClaim::from_bytes`,
  verify the registered bank's signature, store (open handler:
  authentication is the claim signature, mirroring `submit_voucher`'s
  posture — the submitting banks are *not* members of the venue space, so
  role gates cannot carry this); `settle_window(pair, currency, window)` —
  run `cipher_clerk::settlement::reconcile(a, b)`, record the outcome
  (Operator-gated); reads for the watch view (`settled_windows`,
  `pending_claims`, `banks`).
- **Claim-store semantics**: a signed claim for an **unsettled** window is
  replaceable (latest-signed wins) so a bank can resubmit after a
  mismatch; **frozen once settled**. The stored claim body carries a
  version byte — the Wave-2 claim schema will grow state-root/proof fields
  (cipher-clerk's own v0.2 note), and the store must tolerate that without
  migration. The diagnostics args (`voucher_count`, `rk_set_hash`) travel
  *alongside* the signed claim, not inside it, so the cipher-clerk schema
  is untouched.
- **Consistency**: `raft` across the venue's nodes (register from genesis —
  the monotone locality seal forbids widening later). Raft is tier-2 and
  answers the network by design; no `network_reachable` opt-out needed.
- **Leader targeting**: the Operator-gated handlers are subject to the same
  leader-forward caller-identity loss as clerk-ledger (G6) — inbound
  invokes attribute the caller to the connecting peer
  (`vos/src/network/mod.rs:1585-1596`). The demo script targets the venue
  **leader** for `register_bank`/`settle_window` (via `raft-status`), and
  G6's gating test covers clerk-settle, not just clerk-ledger.
- Enable cipher-clerk's `settlement` feature for this crate only.

This is the seam Wave 2 upgrades: same flow and venue surface;
`reconcile` swaps for STARK verification of a settlement statement, and
the claim schema gains state-root/proof bindings.

### S2. Claim production on the banks (G2)

The zero-sum check passes **only** if both banks derive their net flow
from the *same* voucher amount commitments — blindings then cancel by
construction. The construction, normatively:

```
net_flow(bank) = Σ amount_commit(vouchers issued to peer, this window)
              ⊖ Σ amount_commit(vouchers accepted from peer, this window)
```

- **Receiver term (actor-recorded, mandatory)**: clerk-bridge accumulates,
  per `(peer, currency, window)`, the negated sum of accepted vouchers'
  `amount_commit` — updated at the same accept points as the F2 anchor.
  Exposed via a `window_net(peer, currency, window)` read. A claim whose
  net flow does not incorporate this actor-derived term is demo theater;
  the driver **must** combine it (point-add) with its issuer term.
- **Issuer term (driver-recorded)**: voucher issuance is host-driven; the
  per-bank driver (S3) accumulates the issued sum per peer per window,
  persisted across invocations.
- **Window lifecycle on the bridge**: vouchers carry **no window id, no
  timestamp, and no currency** (`cipher-clerk/src/voucher/mod.rs:57-73`) —
  windows are operational brackets, not wire data. The bridge gains an
  Operator-gated `window_rotate(peer)` handler; the receiver-side sum is
  bracketed by explicit rotate events, mirrored by the driver on the
  issuer side (same authority as S4's close).
- **Currency**: a fixed demo constant (e.g. ISO-4217 `840`, matching the
  cipher-clerk test convention), agreed at `register_peer`/`register_bank`
  time — neither vouchers nor bridges carry one. The accumulator is keyed
  with currency from the start so multi-currency never silently mixes
  commitments under one claim.

Worked example (the sign convention is load-bearing): A pays B 10
(voucher V₁, commit C₁); B pays A 3 (voucher V₂, commit C₂). Bank A's
claim nets `C₁ ⊖ C₂`; bank B's nets `C₂ ⊖ C₁`; their sum is the identity
point and the blindings cancel exactly — this is precisely what
cipher-clerk's settlement tests exercise.

### S3. The per-bank driver (G3 — the gap the draft missed)

**No existing component can drive the money flow.** `vosx` cannot sign;
nushell cannot do Ristretto arithmetic; the cipher-clerk CLI's
`cross send` debits its *own file ledger*, not the clerk-ledger actor
(`cipher-clerk/cli/src/main.rs:376-405`); and today voucher/claim
construction exists only inside the e2e test binary.

New small Rust binary in `bloque/bank-federation/src/`: per-bank instance,
each holding **only its own bank's clerk key** and reading **only its own
bank's actors**:

- reads `transfer_state_roots` from its clerk-ledger and
  `window_net` from its clerk-bridge;
- builds and signs vouchers (cipher-clerk library) anchored to the actor's
  real state roots; ships bytes via `vosx space call … key=@file` (which
  already passes `Vec<u8>` — G29 is polish, not a prerequisite);
- maintains the issuer-side accumulator per `(peer, currency, window)`,
  persisted across invocations;
- derives, signs, and submits `SettlementClaim`s.

Two independent driver instances (one per bank) are what make the
settlement beat honest at Wave-1 trust (§1). One process holding both
keys would verify the script against itself.

### S4. Window close, quiesce, and recovery (G4)

- **Quiesce barrier**: `reconcile()` requires *identical voucher sets* on
  both sides of a byte-identical window — one in-flight voucher at close
  makes **both** windows fail `NetFlowDoesNotCancel`, and `reconcile` is a
  bare `Err` with no partial/dispute path. The close script therefore:
  stop issuing → assert every issued `redemption_key` (both directions)
  appears in the counterpart bridge's dedup set → rotate windows → derive
  claims.
- **Divergence diagnostics**: commitments are opaque — a bare mismatch is
  undebuggable. The `voucher_count` + `rk_set_hash` submitted alongside
  each claim (S1) localize a mismatch (count differs ⇒ in-flight/missed
  voucher; count equal but hash differs ⇒ set divergence) without opening
  any commitment. Recovery: resubmit claims for a merged window
  (claim-store replace-until-settled makes this possible).
- **Wedge recovery**: Operator-gated bridge handler
  `anchor_reset(peer, root)` — after a recorded settlement, re-anchor
  `last_root_after` to the settled window's closing root. This makes
  settlement *visibly* the sanctioned recovery for the F2 fail-closed
  wedge, completing the story bank-federation.md deliberately left open.
- Window close authority: demo script for the showcase (chronos-driven
  later).

### S5. Manifests + the Raft gates (G5, G6)

- Manifests (bloque repo): clerk-ledger `consistency = "raft"` (closing
  bank-federation.md item 1), clerk-bridge **`consistency = "local"` +
  `network_reachable = true`** — *not* Ephemeral: the bridge now holds the
  F2 anchor, the dedup set, and the S2 window sums, and Ephemeral is
  in-memory-only ("state is lost when the agent exits",
  `vos/src/node.rs:68-72`); a mid-window bridge restart would zero the
  receiver sum and reopen the replay window. Local is node-confined, so
  the `network_reachable` opt-out is still required. The existing e2e
  already registers the bridge Local — bank-federation.md's "Ephemeral
  bridges" wording gets corrected in the same change.
- **The Raft caller-identity gate comes first** (G6, scheduled Phase 0):
  a 2-node gating test — bootstrap, create accounts, `apply_transfer` via
  the leader, kill/restart a follower, assert state-root convergence —
  specifically probing Operator-gated mutators arriving via leader-forward
  (the forwarded write is attributed to the forwarding node's peer). Its
  resolution (grant node peers the role vs route mutations via the System
  path) **shapes the manifests, the grant script, and clerk-settle's own
  gated handlers** — which is why it precedes them, and why the same test
  covers clerk-settle once it exists.

### S6. The 3-space multi-node e2e (G7)

Extend the federation e2e to the CI gate the live demo actually stands on
— which means multi-node, not just a third space: **venue ×2 + bank-A ×2 +
bank-B ×1 (5 in-process nodes) minimum**. Must assert:

- `submit_claim` arriving at the venue **follower** (cross-space ask →
  leader-forward for the open handler) and `settle_window` at the leader;
- hyperspace resolution from a *second* node of a space;
- **bidirectional vouchers** — today's e2e has no clerk-bridge on bank A at
  all ("our test only flows A→B"), so standing up and accumulating on a
  second bridge is real named scope, not an afterthought;
- window rotate → quiesce → claims from both sides → zero-sum settle →
  `anchor_reset` unwedging a deliberately wedged channel.

Sized L (the 2-bank e2e is ~2000 lines; this composes it with the raft
fixtures).

### S7. Orchestration + demo-day ops (G8, G10, G11)

- Bring-up script (bloque repo, nushell — cloned from `demo-msg-procs`):
  7 isolated-XDG daemons; **per-daemon port allocation table**; ordered
  per-space bring-up (`space new` → `join` → `members add-node` →
  member-tier grants for **both node peers** → poll for "spawned at
  runtime"); full cross-space bootstrap **dial graph** via repeated
  `--connect` (route drops unknown prefixes silently — health-check
  `peers_with_prefixes` before the money flow).
- **Rehearse at least once with mDNS disabled**: single-host rehearsal
  auto-dials over mDNS, silently masking dial-graph errors that a
  multi-machine demo day (P2 drives from a second machine) then hits; on
  venue Wi-Fi, mDNS may also dial stranger peers.
- Beat-3 kill/restart: **wait for process exit** before restarting (redb
  holds an exclusive file lock — a half-dead process blocks the restarted
  daemon's DB open mid-beat).
- `vosx space raft-status <agent>` (G10): role/leader/members from the
  existing RaftStatusReq plumbing — leader targeting (S1), the kill beat,
  and the watch view all key off it. Pre-warm all Raft groups before the
  audience-visible flow (group formation ~6s+).
- Persist the hyperspace name into the space index at first
  `space up --manifest`, re-attach on every boot (G11).
- Runbook line for an **unscripted** daemon death: restart with same XDG +
  manifest, re-run health checks, which beats are resumable.
- Containers (G30): **defer**. Host-run scripts are the showcase vehicle.

### S8. What the audience sees (G9, G29)

Resolving draft open-decision 1 here: the drive surface is the per-bank
drivers + nushell; the visual surface is a minimal **watch view** — a
driver-rendered status table looping `raft-status` across spaces, registry
listings, and the payments/settlements counters. The http-gateway web
dashboard is the *investor-run* upgrade and depends on G27's JSON
rendering; it does not change the spine. `space call … @file` already
carries byte args end-to-end, so G29 (dynamic-dispatcher hex/@file) and
G26/G27a (typed `[u8;N]`, labeled returns) are demo polish, sequenced in
Phase 0 only because they're cheap and de-noise every later step.

### S9. Runbook + talk track (G12)

A deliverable, not an aspiration (lands in `bloque/bank-federation/docs/`):
the trust-framing paragraphs of §1 verbatim; quorum math and safe-to-kill
tables; the recovery procedures (S4 divergence, S7 unscripted death); the
Wave-1/Wave-2 mapping ("what would change if a bank lied"); Q&A traps (the
2-node-quorum question, "is the venue a blockchain?", "who can see my
balance?"). Closing task: update `bank-federation.md` item 1 + Ephemeral
wording when Track S lands.

## 5. Track P — the proving beat

Honest verdict from the numbers (release-canonical, 2026-07-06/07): the
minimal real transfer transition is ~7.56M steps ≈ 76 canonical segments,
~26–29 GB peak per segment, ~22 min chain prove on a 62 GB box; the full
real-STARK e2e ran 3293 s. **Live synchronous proving is not
showcase-viable.** Receiving-side verify is cheap (streaming verify
landed: one ~3 MiB segment at a time, 36–88 ms native verify each) — the
demo leans on that asymmetry, and the economics lean on settlement:
**per-window proving amortizes one proof across all the window's
payments** — the opposite of per-transfer proving.

- **P1. Async prove job (G13, M)**: `prove_chain` is a synchronous
  gas-metered invoke today; the e2e sidesteps the actor system entirely.
  Add a job shape to the prover extension: enqueue → job id → worker
  proves → CAS-publish segments + manifest → tell/callback with the
  manifest hash. Reuses CAS fan-out + the Unify-6 host tick/spawn
  machinery.
- **P2. Rehearse the real-STARK beat on the real topology (G14, S)**:
  precompute the 76-segment chain on the ≥64 GB box, seed bank A's CAS,
  register the separate `bank-a-stark` peer channel, drive
  `submit_voucher` from another machine so manifest + segment fetches and
  streaming verify happen visibly cross-node. Known traps to script
  around: fresh voucher-check ELF + prover `.so`,
  `RUST_MIN_STACK=268435456` on the verifying node, frame-cap-respecting
  per-segment CAS delivery. The most likely demo-day failure if left
  unrehearsed.
- **P3. Turnkey re-pin tool (G15, M)**: for a chosen `seg_steps`, emit the
  canonical profile + `{C_i}` allowlist mechanically (today a hand flow
  that has bitten twice). Unlocks the ~12K-step / ~4 GB configuration if
  demo hardware demands it; prerequisite of `#[provable]`'s pin story.
- **P4. Fix the silently-skipping settle tests (G16, S)**: two test paths
  still say `recursion-verifier`; the crate is `settlement-verifier`
  (`zkpvm/tests/settle_run.rs:29`, `settle_transpile.rs:15`). Until fixed,
  the 10.7M-cycle PVM-verify claim is unreproducible via the documented
  flow. Do first.

### 5.5 How proving plugs into refine/accumulate — and where streaming fits (G17)

The user's contingency question, answered concretely rather than deferred:

- **The attachment point is the refine boundary.** Refine is the only
  guest execution (§0.2); its inputs are exactly what the witness buffer
  carries, and its public outputs (state roots, commitments) are what the
  io-hash binds. The async prove job (P1) is therefore "re-derive the
  refine witness, prove off the hot path" — nothing about commit changes.
- **Commit is not gated in Waves 1–2 (optimistic commit, proof follows).**
  The ledger's native journal replay commits immediately; proofs attach to
  *value crossing trust boundaries* — `Mode::External` vouchers and,
  later, settlement claims. The venue/receiver demands proof at
  **settlement time**, bounding value-at-risk to one window. This is the
  economically sane shape: prove per window, not per transfer.
- **Verify-before-commit is the high-assurance variant** — gating
  accumulate's replay on proof verification. It is only plausible
  *receiver-side*, because streaming verify is cheap; it is exactly what
  `verify_chain` already does before `redeem_voucher` dispatches. Making
  it a first-class actor property (an agent whose inbound effects only
  commit with proof) is a natural Wave-2+ follow-on, not showcase work.
- **The streaming prover slots into the per-segment pipeline.**
  `prove_chain_segments` already iterates segment-by-segment; the
  streaming prover bounds RAM *within* a segment (chunked trace-column
  commit against the ~26–29 GB wall), giving:
  refine trace → per-segment witness → prove (bounded RAM) → CAS-publish
  incrementally → manifest finalized at window close. Segments prove
  concurrently with later payments; the window close waits on the
  manifest, not the other way around.
- **Order of work**: SideNote diet first (independent, mechanical, ~10×
  trace RAM, unlocks parallel segments on existing hardware), then the
  chunked-commit spike on the stwo fork. Native recursive aggregation is
  formally dead (per-join ~600–750M instructions; machinery archived at
  tag `voucher-recursion-archive`); the aggregation question is now the
  Track-B fork (sum-check rearchitecture vs SNARK wrap), which the
  streaming prover does not wait on.
- **Contingency trigger, restated**: if cross-ledger transfers must be
  proven per-transfer at production cost — i.e. if per-window settlement
  proofs turn out not to satisfy the trust requirements of real
  counterparties — the streaming prover (and the SideNote diet before it)
  moves ahead of Track E. Re-evaluate after Phase 3's rehearsal numbers.

The full design note (chunked commit vs FRI/logup interaction, upstream
stwo conversation) is a Phase-0 deliverable — writing it is days, and it
de-risks the biggest unknown early even though implementation stays in
Phase 5.

## 6. Track E — production-readiness ergonomics

None of these block the showcase; all three make the *next* actor an
order of magnitude cheaper to write. One exception to "after the
showcase": **G25 (custom rkyv args) lands before S1/S2 freeze their
handler signatures**, so clerk-settle and the bridge's new handlers are
born typed instead of being written in the `Vec<u8>` idiom and retyped in
Phase 4 (§5 and §8 of the draft disagreed here; this is the resolution).

### E-A. Full-fidelity `#[msg]` arguments (G25–G29)

Today the macro accepts a 12-variant scalar vocabulary; anything else is
`Vec<u8>` + manual decode. 66 of 143 handlers take at least one `Vec<u8>`
arg; ~30–40 would become typed (the rest are genuinely opaque — MLS
ciphertexts, proofs, blobs). The typed path already exists end-to-end for
*returns* and for non-dynamic dispatch; the core work unblocks the
dynamic-path accessor and the sender-side bound:

1. **Custom rkyv structs as args (G25, M — pulled forward)**: `from_msg`
   falls back to checked `rkyv::from_bytes::<T>` for non-whitelist types;
   Ref-side encodes into `Value::Bytes`. Wire format unchanged; old
   callers keep working. Then delete the `decode_or_bad_input!` idiom and
   retype the clerk handlers. `Vec<[u8;32]>` as an arg type also retires
   the concatenated allowlist framing on the showcase path.
2. **`[u8; N]` (G26, S)** and **return-type names in `MessageMeta`
   (G27a, S/M)**: cheap, de-noise the whole demo (ids/roots length-checked;
   reply hex at least labeled).
3. **Checked reply decode (G28, S)**: the generated Ref currently
   `access_unchecked`s peer-supplied reply bytes — cross-space replies
   cross trust boundaries, so a malicious or version-skewed peer reply is
   UB today. Switch to checked `rkyv::access` + `ClientError::Decode`.
   Security-relevant: Phase 0.
4. **Nested type descriptors + JSON↔rkyv (G27b, L)**: a `VosSchema`-style
   derive emitting const field trees into `.vos_meta`; the gateway grows a
   descriptor-walking JSON→rkyv serializer, vosx the inverse. Scope v1 to
   structs of supported scalars + `[u8;N]`, one nesting level. This is
   what makes custom args usable from *outside* Rust — and what the
   investor-run web dashboard (S8) waits on.

### E-B. Agent + sub-actor model — **superseded by `vos-core-execution.md` §3.3**

The 2026-07-08 design challenge inverted this section's premise. The
"in-journal children inherit the parent's tier" constraint is not a bug to
route around — it is JAM's one-service atomicity, and parent-owned
stateless children are the **only** composition shape JAR refine licenses
(nested PVM via `machine`). The design is now `vos::agent::Tasks` with
`Child::{Task(code_hash), Peer(service_id)}`:

- **Task** (primary, JAM-aligned): anonymous pure blob, no ServiceId/row;
  state lives in the parent's committed `TaskRecord`; suspension is a
  value; resume is cold re-invocation.
- **Peer** (this section's old design, still necessary): a registry agent
  for children needing their own consistency tier, ACL surface, or
  external addressability — the messenger's msg-log(crdt)+msg-ctl(raft)
  case. What survives from the old plan: teardown/uninstall propagation
  (G20), Status/Role derive macros + porting messenger `clients.rs` to
  generated Refs (G21), intra_caps emission, name-collision checks.

### E-C. `#[provable]` — **superseded by `vos-core-execution.md` §3.4–3.5**

The challenge upheld this section's key correction (return type = the
public statement; state roots bound; purity guard) and strengthened it:
`#[provable]` generates a **dedicated single-op proof-guest per annotated
function** (one op = one program = one pinned commitment — no witness
discriminator), the live Task invocation and the traced re-execution share
one witness-delivered input ABI (killing the dual-commitment problem), and
the parent always-captures a compact `ProvableRecord` (+ secret witness in
CAS) so proving is on-demand. Build centralization (G24: guest toolchain,
cipher-clerk `.wt_alt` path dep) and the `vosx zk pin` catalog tool carry
over unchanged.

## 7. Parallel workstreams (decided 2026-07-08: VOS core first)

The work splits into six streams with **disjoint file footprints**, each
developable simultaneously in its own branch + worktree (or its own repo).
The core streams (A, D) are the priority — they fix the framework
everything else is written in; the showcase streams (C, E, F) and the
proving stream (B) proceed alongside because they don't touch the core's
files.

| WS | Scope | Owns (exclusive footprint) | Coupling |
|----|-------|----------------------------|----------|
| **A — vos core** | Execution-model arc from `vos-core-execution.md` §4: bug fixes (A0–A6) → work-result contract (A7–A8) → Tasks + code-hash invoke (A9–A11) → determinism/checkpoints (A12–A13) → JAM apply (A15) | `vos/src/runtime.rs`, `node.rs`, `commit.rs`, `refine_payload.rs`, `actors/*`, `data_layer.rs`, `effect_log.rs` | none inbound; B4/B5 wait on A8/A9 |
| **B — proving** | B1 streaming-verify anchor · B2 `#[provable]` v1 · B3 `vosx zk pin` · B6 `vos::zk::state` · B7 proof-clerk · B8 async prove (P1) · B9 settle-test paths (P4) · then B4/B5 with A | `zkpvm/`, `extensions/prover/`, `vos/src/zk.rs`, cipher-clerk (succinct extraction) | B2 lands in vos-macros via stream D's queue; B4/B5 after A8/A9 |
| **C — clerk/settlement** | G6 raft caller-identity gate FIRST (its answer shapes manifests, grants, and clerk-settle's gated handlers) → S1 clerk-settle (new crate) → S2 bridge windows/claims → S4 close/quiesce/reset → S5 manifests → S6 multi-node e2e | `actors/clerk-settle/` (new), `actors/clerk-bridge/`, `actors/clerk-ledger/`, `examples/`, `vos/tests/` (append-only) | handler typing waits on D's G25 (or handlers are born `Vec<u8>` and retyped — D is small, prefer waiting) |
| **D — macros & typed args** | G28 checked reply decode (security, first) → G25 custom rkyv args → G26 `[u8;N]` → G27a return-type names → B2 `#[provable]` macro v1 (queued last, same file) | `vos-macros/`, then vosx/http-gateway rendering bits | serialized internally — vos-macros/src/lib.rs is one file; feeds C and B |
| **E — showcase ops & driver** | S3 per-bank driver binary · S7 orchestration scripts (9 daemons) · S8 watch view · S9 runbook + talk track | **bloque/bank-federation** (whole separate repo) | interface dep on C's claim/window handler signatures; voucher flow can start now (already shipped) |
| **F — vosx & small ops** | G10 raft-status CLI · G11 hyperspace persistence · G29 dispatcher bytes | `vosx/` | none |

Contention rules that make this safe: **runtime.rs/node.rs/commit.rs
belong to A alone** (B's capture/witness-invoke steps are explicitly
sequenced after A's); **vos-macros belongs to D alone** (B2 queues there);
`elf_integration.rs` is append-only by convention (A and C both add
tests — rebase-friendly); cipher-clerk is modified only by B6 (C consumes
it as a dependency).

Ordering within the decided priority: A0–A6 and D's G28/G25 are the
immediate starts (bug fixes + the macro core everything downstream wants);
C starts with G6 in parallel; E starts with the voucher-flow half of the
driver. Phase 5 material (SideNote diet → streaming prover implementation,
settlement guest de-fixturing, G30 containers) stays sequenced after the
core arc; the §5.5 contingency trigger is re-evaluated after B8 + the
real-STARK rehearsal (P2).

## 8. Decisions

Resolved 2026-07-08 (user):

1. **Topology: 9 daemons** (×3 per space — kill-anything freedom).
2. **`clerk-settle` lives in vos `actors/`**; clerk-bridge stays (per-bank
   ingress; the settlement design makes it more load-bearing, not less).
3. **Venue consistency: Raft** — Raft is the default for the clerk stack.
4. **VOS core first**: the `vos-core-execution.md` arc leads; showcase
   streams run in parallel worktrees (§7).

Still open:

5. **Window close authority**: demo script (recommended) vs chronos-driven
   from day one.
6. The execution-model decisions in `vos-core-execution.md` §5 (jar entry
   ABI resolved 2026-07-08: graypaper jump-table; still open — time/entropy
   policy under replication, witness-ABI scope, invoke envelope bound,
   secret-witness retention).

## 9. Non-goals (this plan)

- Proof-verified settlement on the venue (Wave 2; the seam is S1's
  versioned claim store — `reconcile` swaps for STARK verification of a
  settlement guest, claims gain state-root/proof fields).
- Operator-blind banks, BFT/public banks (Wave 2, per bank-federation.md).
- Hyperspace hardening (G31: authenticated `register_remote`, bridge
  admission) — the showcase is explicitly Wave-1 trusted-operator; the
  talk track says so rather than pretending otherwise.
- Per-transfer live proving (the economics point the opposite way:
  settlement amortizes one proof across a window; see §5.5 for the
  contingency that would reverse this).
