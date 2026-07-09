# VOS roadmap — status and what's next

One place to resume from. The design rationale behind the landed work lives
in git history and the design contracts under `docs/design/`; this doc is
the forward-looking essential: what shipped, what remains, and how to run
the bank-federation demo.

Companions that stay authoritative (do not fold away):
- `docs/design/work-result-contract.md` — RefinePayload v3 wire + the §5
  proving seam. **§5 is the spec B4 implements.**
- `docs/design/jam-entry-points.md` — JAM entry-prologue convergence; the
  spec for the remaining jar Phase-1 items.
- `docs/design/masked-image-root.md` — the Level-2 entering-image pin.
- `docs/plans/bank-federation.md` — the wave model (the north star:
  heterogeneous banks settle over a shared voucher/settlement protocol).
- `docs/plans/proving-time.md`, `succinct-merkle-witness.md` — proving cost
  + the transition proof.

## 1. What landed (2026-07, all on master + pushed)

The VOS-core execution model was rebuilt so that **live execution ≡ traced
execution ≡ a proof that commits to the state transition**, under a working
bank federation, without regressing it.

- **A0–A6** runtime bug-fixes: discard-on-panic, commit-then-outbox,
  blake2b blob addressing, STATUS_TOO_BIG, deleted dead guest-accumulate
  scaffolding.
- **A7–A9 keystone**: RefinePayload v3 (state-as-effect, per-tick anchor
  chain, transition digest); whole-agent `AgentDelta` commit unit; the
  **witness-delivered Task ABI** — a `#[actor(task)]` invocation patches
  `(state,msg)` into the child image at `__VOS_WITNESS`, the same channel
  the zkpvm tracer patches, so live and traced images are byte-identical
  (live≡proved, confirmed by a non-vacuous gate). `vos::agent::Tasks`
  {`Task(code_hash)`, `Peer(service_id)`} + scheduler ported onto it.
- **B2 proving seam**: `run_task_service` composes
  `io_hash(folded_public(anchor_kind, anchor, transition_digest,
  app_public), reply)` at halt — a Task's proof commits to its transition,
  not a placeholder. Handlers designate public inputs via
  `vos::zk::bind_public`.
- **B1/B3/B8 proving pipeline**: `verify_chain` enforces an entering-image
  anchor and the deployed federation producer ships an anchored manifest
  (mid-chain-splice gap closed on the money path); the `vosx zk pin`
  catalog is the allowlist source; an async prove job (enqueue → job id →
  tick worker → CAS publish → callback).
- **Federation (Wave 1)**: clerk-ledger/clerk-bridge + `clerk-settle`
  venue; voucher issue → ship → redeem; per-peer/window net-flow
  accumulation → signed `SettlementClaim` → venue zero-sum reconcile;
  receiver-side F2 anchor + post-settlement `anchor_reset`; multi-node
  3-space capstone e2e.
- **Ergonomics**: typed `#[msg]` args (custom rkyv structs, `[u8;N]`,
  checked reply decode), `vosx space raft-status`, hyperspace persistence,
  space-scoped `auto_replication_id`.
- **jar (github.com/olanod/jar)**: JAM-alignment Phase 0 (hard-fork policy)
  + Phase 1 (host-owned SP, args ω7/ω8, refine IC 0 / accumulate IC 5,
  two-slot jump prologue; jar1 conformance gate holds, gp072 untouched).

## 2. The bank-federation demo (Stream E) — the last step to a runnable demo

Goal: bank A (a space) pays bank B (a space), settling on a third parent
(venue) space; 3 spaces × 3 nodes each (9 daemons) to show CRDT/Raft
replication. Setup lives in `/home/daniel/src/bloque/bank-federation`.

**Architecture (no new Rust crate).** Everything is toml manifests +
nushell/just scripts, glued from two existing tools:
- **vosx** — actor dispatch: `space call clerk-ledger apply_transfer …`,
  read `transfer_state_roots`, `submit_voucher voucher=@file`,
  `space raft-status` for leader targeting. Typed args + `@file` are on
  master.
- **cipher-clerk CLI** — the crypto. It already has `Voucher::sign` /
  `SettlementClaim::sign`, **but they're wired to its own file ledger**
  (`state.ledger.root()`), so they can't sign against the *actor's* roots.

**The one code change needed:** add ~3 explicit-input signing subcommands to
the cipher-clerk CLI, decoupled from any file ledger —
`voucher sign --amount --blinding --root-before --root-after --key`,
`claim sign --net-flow --pair --currency --window --key`, and a
`commit add --a --b` (Pedersen point-add for the issuer accumulator). Then
bloque = declarative manifests + scripts.

**The money flow, per script step:**
1. `vosx space call clerk-ledger apply_transfer …` (debit on bank A's ledger)
2. `vosx space call clerk-ledger transfer_state_roots <id>` → read
   `(root_before, root_after)`
3. `cipher-clerk voucher sign --root-before … --root-after … --key bank-a.key`
   → signed voucher bytes anchored to the *actor's* real roots
4. `vosx space call clerk-bridge submit_voucher voucher=@voucher.bin peer_name=…`
   (bank B verifies + accumulates the receiver term)
5. At window close: each bank derives `net_flow = issuer_accumulator ⊕
   bridge.window_net`, `cipher-clerk claim sign`, then
   `vosx space call clerk-settle submit_claim` — **targeting the venue
   leader** (there is no follower auto-forward for the open write; use
   `raft-status`)
6. `vosx space call clerk-settle settle_window …` → zero-sum reconcile
7. `cipher-clerk anchor_reset` on both bridges → unwedge for the next window

**Two independent per-bank scripts, one key file each** — that's what keeps
the settlement honest (each bank's claim is independently derived; a single
process holding both keys would verify the script against itself).

**Topology + ops (the traps, already learned):**
- 9 daemons: bank-a ×3, bank-b ×3, venue ×3, shared
  `hyperspace = "bank-federation"`. ×3 so any node (incl. a leader) can be
  killed on stage and the space keeps serving (a 2-voter Raft group has
  quorum 2 = zero fault tolerance).
- clerk-ledger `consistency = "raft"`; clerk-bridge `local` +
  `network_reachable = true` (**not** Ephemeral — the bridge holds the F2
  anchor + dedup + window sums; Ephemeral wipes them on restart).
- **Pin a distinct `replication_id` per bank** in the manifests (or the
  master fix makes `"auto"` space-scoped now — either works; pinning is
  explicit).
- Cross-space routing needs a full libp2p dial graph (route silently drops
  unknown prefixes) — build every pair's `--connect`, health-check
  `peers_with_prefixes` before the money flow; rehearse once with mDNS
  disabled so the dial graph is proven load-bearing.
- Quiesce barrier before window close: stop issuing → assert every issued
  `redemption_key` appears in the counterpart bridge's dedup set →
  `window_rotate` both directions → derive claims. (`reconcile` demands
  identical voucher sets on a byte-identical window; one in-flight voucher
  fails *both* windows.)
- Operator-gated venue handlers (`register_bank`, `settle_window`) arrive
  via leader-forward as the *forwarding node's* peer — grant each voter
  node's own peer `Admin`, or target the leader directly.

**Reference manifests already exist** in this repo:
`examples/space-bank-a.toml`, `space-bank-b.toml`, `space-venue.toml`
(clerk-ledger raft, clerk-bridge local+network_reachable, venue
clerk-settle raft, shared hyperspace) — mirror their postures.

**Demo beats worth showing** (for a Bloque/investor audience): intra-bank
instant payment (no chain); a Raft failover (kill bank-a's leader, payment
still succeeds); a privacy beat (cross-bank ledger read → `Forbidden`; a
claim shows only Pedersen commitments, never amounts); cross-bank payments;
the settlement beat (N payments → 1 settlement on the venue); and — framed
honestly as the Wave-2 backstop — one real conservation STARK verified
cross-node via streaming verify (precompute the ~76-segment chain offline;
it's minutes + ~28 GB/segment, not a live prove).

**Trust framing to say out loud:** Wave 1 = mutually-known operators,
signature-trusted; the venue checks mutual *consistency* of the two banks'
books, not solvency; the venue stands in for the on-chain settlement venue
(Wave 2 moves claim verification on-chain — `settle.elf` is that verifier).

## 3. Remaining work (prioritized)

**Near-term / demo-adjacent**
- **Stream E** (§2) — the driver + scripts + runbook. The demo.
- **B4** — verify-side proving: capture a `ProvableRecord` (anchor,
  transition_digest, app_public, roots) per provable invocation and a
  `verify_call` that reconstructs `public'` and checks the bound io-hash.
  **Trap (documented in work-result-contract.md §5):** the guest digests
  effects *including* the final `Write{STATE_KEY}`; the reconstruction must
  digest the same (pre-`take_state_write`) or every check fails.

**Keystone fast-follows (non-blocking; the merged code is green)**
- Ristretto precompiles fail-loud in live Task mode (the tracer handles
  them) → add host handlers to `handle_task_hostcall`, or document
  trace-only. cipher-clerk value-transfer proving needs this.
- Always-run regression fixtures for guest-side money-path behaviors
  (fieldless-self-tell anchor, mid-chain panic reply-drop, child-invoke
  rollback) — currently only ELF-gated.
- **A10 pre-req**: a Task's non-STATE effects are dropped on replica
  rebuild (DAG replay short-circuits depth-1 invokes) — fix before wiring
  Tasks into replicated agents (re-run in-runtime Task invokes on replay,
  or restrict Task effects to STATE_KEY + transfers).

**VOS-core continuation (design in vos-core-execution's A-list, mostly
future)**
- A11 `vos::task` step-machine combinators; A12 determinism tiers (record
  NOW_MS / deny BOOT_CONTEXT under Crdt/Raft, hostcall-tier marker in
  `.vos_meta`); A13 DAG checkpointing (bounded replay); A15 guest
  accumulate as a thin APPLY behind the jump prologue (gated on jar
  Phase 1's entry-table — mostly done); A17 stale-anchor reconciliation
  spike (prereq for parallel refine).

**jar JAM-alignment (platform track — the demo does NOT depend on it)**
- Phase-1 remainder: GP halt-address / REPLY-retirement, ISA strictness
  (reject opcode 3, branch-target validation), interpreter/JIT
  page-permission parity.
- Phases 2–7 in the jar `ROADMAP.md`: turn the gp072 vector ratchet on,
  SPI loader + PVM vectors, hostcall convergence, the economics decision
  (coinless vs BalanceEcon — gates any "JAM conformant" claim), the in-core
  pipeline, advancing the GP pin.

**Wave 2 (federation, future)**
- On-chain settlement-verifier (the cross-type trust bridge); operator-blind
  banks (client-side proving); the masked-image-root Level-2 pin
  (`docs/design/masked-image-root.md`).

## 4. Ops notes worth keeping

- Rebuild actor ELFs before e2e runs: `just build-actors` and (repo root)
  `just build-pvm`; `just test-pvm` does both. `cargo test` rebuilds the
  rlib but NOT the actor `.so`/ELF — stale ELFs are a recurring trap.
- Heavy real-prove tests are `#[ignore]` by convention (minutes,
  ~28 GB/segment); the cheap paths (anchor reject, catalog parity, the
  live≡traced gate) run in the normal flow.
