# VOS roadmap and reference

The single place to resume from. Parts 1–3 are the forward plan (status,
the bank-federation demo, remaining work). Part 4 is the folded reference —
the load-bearing essentials of the design contracts and domain docs. Full
byte-level history for any of these lives in git.

## 1. What landed (2026-07, on master + pushed)

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
  app_public), reply)` at halt — a Task's proof commits to its transition.
  Handlers designate public inputs via `vos::zk::bind_public`.
- **B1/B3/B8 proving pipeline**: `verify_chain` enforces an entering-image
  anchor and the deployed federation producer ships an anchored manifest
  (mid-chain-splice gap closed on the money path); the `vosx zk pin` catalog
  (measured by the prover extension's `measure_catalog` handler) is
  the allowlist source; an async prove job (enqueue → id → tick worker →
  CAS publish → callback).
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

## 2. The bank-federation demo (the last step to a runnable demo)

Goal: bank A (a space) pays bank B (a space), settling on a third parent
(venue) space; 3 spaces × 3 nodes (9 daemons) to show CRDT/Raft
replication. Setup lives in `/home/daniel/src/bloque/bank-federation`.

**Architecture: pure VOS actors + `vosx` + scripts. No new tool, no crypto
CLI.** Voucher/claim signing moves *into the clerk actors* (they already
link cipher-clerk and the bridge already holds a secret and verifies
signatures — signing is the mirror of what it does today):
- **`issue_voucher`** handler on the issuing side — clerk-ledger already
  computes `amount_commit`, `root_before`, `root_after` at transfer time;
  given the bank's clerk key it returns signed voucher bytes.
- **issuer-side accumulation** on the bridge — the mirror of the receiver
  `window_net` accumulator it already keeps.
- **`sign_claim`** handler — composes `issuer ⊕ receiver` net-flow and
  signs the `SettlementClaim`.
- **Key custody:** device-secret provisioning (node-local, *not*
  Raft-replicated), so the clerk secret stays off the log while ledger
  state replicates. Each bank's actor signs with its own key — preserves
  the "two independent banks, one key each" honesty (a single signer would
  make the venue's zero-sum check verify a script against itself).

Then the whole driver is `vosx space call` + nushell/just scripts.

**Money flow per step:**
1. `vosx space call clerk-ledger apply_transfer …` (debit bank A's ledger)
2. `vosx space call clerk-ledger issue_voucher <transfer_id> peer=bank-b`
   → signed voucher anchored to the *actor's* real roots
3. `vosx space call clerk-bridge submit_voucher voucher=@voucher.bin
   peer_name=bank-a` (B verifies + accumulates the receiver term)
4. window close: `vosx space call clerk-bridge sign_claim peer=… window=…`
   on each bank (composes issuer⊕receiver, signs) →
   `vosx space call clerk-settle submit_claim …` **at the venue leader**
   (no follower auto-forward for the open write; find the leader via
   `raft-status`)
5. `vosx space call clerk-settle settle_window …` → zero-sum reconcile
6. `vosx space call clerk-bridge anchor_reset …` on both bridges → unwedge

(If the signing handlers aren't built yet, the fallback is host-side
signing via the cipher-clerk *library* in a tiny per-bank script — but the
in-actor handlers above are the intended shape and keep bloque = toml +
scripts only.)

**Topology + ops traps (already learned):**
- 9 daemons: bank-a ×3, bank-b ×3, venue ×3, shared
  `hyperspace = "bank-federation"`. ×3 so any node (incl. a leader) can be
  killed on stage and the space keeps serving (2-voter Raft = quorum 2 =
  zero fault tolerance).
- clerk-ledger `consistency = "raft"`; clerk-bridge `local` +
  `network_reachable = true` (**not** Ephemeral — it holds the F2 anchor +
  dedup + window sums; Ephemeral wipes them on restart).
- Pin a distinct `replication_id` per bank (or rely on the now
  space-scoped `auto`).
- Cross-space routing needs a full libp2p dial graph (route silently drops
  unknown prefixes) — build every pair's `--connect`, health-check
  `peers_with_prefixes` before the money flow; rehearse once with mDNS off.
- Quiesce barrier before window close: stop issuing → assert every issued
  `redemption_key` is in the counterpart bridge's dedup set →
  `window_rotate` both directions → derive claims. (`reconcile` demands
  identical voucher sets on a byte-identical window; one in-flight voucher
  fails *both* windows.)
- Operator-gated venue handlers arrive via leader-forward as the
  *forwarding node's* peer — grant each voter node's own peer `Admin`, or
  target the leader directly.

**Reference manifests already exist**: `examples/space-bank-a.toml`,
`space-bank-b.toml`, `space-venue.toml` — mirror their postures.

**Beats:** intra-bank instant payment → Raft failover (kill bank-a's
leader, payment still lands) → privacy (cross-bank ledger read →
`Forbidden`; a claim shows only Pedersen commitments, never amounts) →
cross-bank payments → *N payments → 1 settlement* on the venue → and framed
as the Wave-2 backstop, one precomputed real STARK verified cross-node via
streaming verify (minutes + ~28 GB/segment offline, not a live prove).

**Trust framing (say it out loud):** Wave 1 = mutually-known operators,
signature-trusted; the venue checks book *consistency*, not solvency; it
stands in for the on-chain settlement venue Wave 2 makes real.

## 3. Remaining work (prioritized)

**Near-term / demo-adjacent**
- **The demo** (§2): the in-actor signing handlers (`issue_voucher`,
  issuer accumulation, `sign_claim`, device-secret key) + bloque scripts +
  runbook.
- **vosx decoupling** → [vosx-decoupling.md](vosx-decoupling.md): retire the
  hardcoded `ai`/`dev`/`console` commands in favor of the metadata-driven
  dispatcher (docs + jobs + signing in `.vos_meta`), move system-actor
  protocol (registry/chronos) into `vos`, end with zero actor/extension
  crate deps in `vosx`.
- **B4 verify-side proving**: capture a `ProvableRecord` (anchor,
  `transition_digest`, `app_public`, roots) per provable invocation and a
  `verify_call` that reconstructs `public'` (§4.1) and checks the bound
  io-hash. **Trap:** the guest digests effects *including* the final
  `Write{STATE_KEY}`; the reconstruction must digest the same
  (pre-`take_state_write`) or every check fails.

**Keystone fast-follows (non-blocking; merged code is green)**
- Ristretto precompiles fail-loud in live Task mode (the tracer handles
  them) → add host handlers to `handle_task_hostcall`, or document
  trace-only. cipher-clerk value-transfer proving needs this.
- Always-run regression fixtures for guest-side money-path behaviors
  (fieldless-self-tell anchor, mid-chain panic reply-drop, child-invoke
  rollback) — currently ELF-gated.
- **A10 pre-req**: FIXED — the effect log records each depth-1
  invoke's absorbed effects alongside its output, and the replay
  short-circuit re-absorbs them (`replay_reabsorbs_task_effects` is
  the gate). Tasks can now run on replicated agents.

**VOS-core continuation**
- **Actor storage scale-out** → `docs/plans/actor-storage.md`: typed
  storage handles (`StorageMap`/`StorageVec`/`StorageSet`) over the
  existing agent KV — per-key rows instead of the monolithic state blob,
  touched-set-bounded guest memory, **no new hostcalls** (JAM keeps
  `STORAGE_R` accumulate-only; iteration is self-indexed pages, and the
  W4 SMT doubles as the ordered index). W1 delete effect + ordered
  `ServiceStorage`; W2 prelude types + `#[storage]` fields; W3
  space-registry + clerk-bridge adoption; W4 `anchor_kind 0x02`
  committed storage (B6 / `vos::zk::state`) + clerk-ledger at 10k
  accounts.
- A11 `vos::task` step-machine combinators; A12 determinism tiers (record
  NOW_MS / deny BOOT_CONTEXT under Crdt/Raft; hostcall-tier marker in
  `.vos_meta`); A13 DAG checkpointing (bounded replay); A15 guest
  accumulate as a thin APPLY behind the jump prologue (gated on jar Phase 1
  entry-table — mostly done); A17 stale-anchor reconciliation spike (prereq
  for parallel refine).

**jar JAM-alignment (platform track — the demo does NOT depend on it)**
- Phase-1 remainder: GP halt-address / REPLY-retirement, ISA strictness
  (reject opcode 3, branch-target validation), interp/JIT page-permission
  parity.
- Phases 2–7 (jar `ROADMAP.md`): turn the gp072 vector ratchet on; SPI
  loader + PVM vectors; hostcall convergence; the economics decision
  (coinless vs BalanceEcon — gates any "JAM conformant" claim); the in-core
  pipeline; advance the GP pin.

**Wave 2 (federation, future)**
- On-chain settlement-verifier (cross-type trust bridge); operator-blind
  banks (client-side proving); the masked-image-root Level-2 pin (§4.3).

## 4. Reference (folded design contracts + domain)

### 4.1 RefinePayload v3 + the proving seam (was `work-result-contract.md`)

The byte-defined "what a refine produced", applied identically by the host
drain, the child-invoke conversion, the (future) guest accumulate, and any
prover/verifier.

Wire v3: `version(0x03) | flags | anchor_kind | anchor[32] | reply | effects`.
- **State-as-effect**: post-dispatch state is the *final*
  `Effect::Write{STATE_KEY}`, only when changed — kills the old host/guest
  persistence fork. Effects apply in wire order, last-wins per key. Strict
  canonical decode (reject trailing/unconsumed bytes) so "the wire bytes"
  is well-defined for the digest.
- **Anchor** commits to the state the refine ran against:
  `0x00` genesis (STATE_KEY absent or empty), `0x01`
  `blake2b(prior STATE_KEY blob)`, `0x02` reserved SMT root. Effective
  state = the **journal-overlay** (`journaled_read`): a tick's ≤64
  self-message re-entries form an **anchor chain** (iteration N anchors
  N−1's overlay state, not end-of-tick storage). Mismatch ⇒ reject +
  cold-restart; empty state carries genesis (a fieldless actor must not
  self-drop — the landed A7 blocker fix).
- **Apply**: verify anchor → apply effects in order (transfers deferred to
  after durable commit) → all-or-nothing with the dispatch → reply only on
  Ok. Host bookkeeping writes (continuation) are excluded from the digest
  and must never target STATE_KEY.
- **AgentDelta**: the durable commit unit is the *whole agent's* dispatch
  delta (STATE + any non-STATE writes) in one redb txn, with `(kind,
  anchor)` recorded in **every** log node — replay divergence is detected
  by comparing re-emitted anchors against the recorded ones (the self-check
  passes trivially on replay).
- **§5 proving seam (landed producer side)**:
  `public' = anchor_kind(1) || anchor(32) || transition_digest(32) ||
  app_public` (fixed-width prefix ⇒ injective). `run_task_service`
  composes `io_hash(public', reply)` at halt from the payload's own fields;
  a provable handler adds `app_public` via `vos::zk::bind_public`;
  `bind_io`'s finished-hash form is ignored for Task blobs.
  `transition_digest` is over the effects **including** the final
  STATE_KEY write — **B4's verify-side reconstruction must digest the same
  bytes (pre-`take_state_write`)**. Sound only when composed with the
  entering-image-root check (§4.2/§4.3): the state anchor and the image
  root do different jobs; neither subsumes the other. Provable Tasks are
  always cold; `return` = the payload's exact reply bytes.

### 4.2 JAM entry-point convergence (was `jam-entry-points.md`)

Converge the jar fork on the graypaper entry prologue. **Landed (jar Phase
1)**: host-owned SP (`φ[1]=stack_top` at kernel init; in-blob preamble
dropped), args at `ω_7/ω_8`, refine IC 0 / accumulate IC 5, φ[7]=1 selector
retired, two-slot jump prologue (IC 0→e_entry, IC 5→exported `accumulate`
symbol or a trap for refine-only blobs). Ψ_T is gone (transfers are
accumulate inputs). **Remaining Phase-1**: GP halt-address /
REPLY-retirement (refine output still packed in φ[7]), ISA strictness
(reject opcode 3, validate branch/djump targets against basic-block
starts), interp/JIT page-permission parity. **vos A15** wires a thin guest
accumulate APPLY behind this prologue; rebuilding provable actors under the
new prologue requires re-pinning the zk commitment catalog.

### 4.3 The masked image root (was `masked-image-root.md`)

Level-1 (shipped): the chain manifest carries `initial_root`; `verify_chain`
anchors segment 0's `memory_root` to it — content-addressed, so the entering
image is committed/auditable/tamper-evident. Level-1 does **not** prove the
declared root is the *genuine* program image (a producer builds the manifest
to match its own segment 0). The catalog's `unpatched_image_root` can't be
that pin: the witness-delivered ABI patches `(state,msg)` into
`__VOS_WITNESS`, so the live segment-0 root is the **patched** image root
(witness present, secret, per-proof) while the catalog stores the
**unpatched** root — they differ exactly in the witness region, which must
stay free. **Level-2 (design, not built)**: a **masked image root** —
exclude the `__VOS_WITNESS` region from the hashed image so the pinned value
is invariant under the witness while fixing everything else (code,
constants, other data). `unpatched_image_root` is a diagnostic today, wired
to no verifier.

### 4.4 Federation wave model (was `bank-federation.md`)

Different institutions run different banks; the federation doesn't unify
their internal models, it agrees on a **wire** (voucher + on-chain
settlement). A bank's internals (consensus, storage, operator visibility)
stay private; what crosses is a voucher attesting a conservation-of-value
transition, backed by a signature and/or a zk proof; the **settlement
venue is the cross-type trust bridge**. Waves: **1 (now)** regulated/private
banks, Raft across the operator's nodes, operator-visible (trusted clerk),
`Mode::Signature` or the `Mode::External` real-STARK path; **2+ (future)**
public/BFT banks and privacy-first operator-blind banks (client-side
proving), settling to a shared on-chain verifier. Wave-1 gates on the
receiver-side F2 anchor (landed) + the on-chain settlement-verifier
(Wave 2).

### 4.5 Proving cost (was `proving-time.md` + `succinct-merkle-witness.md`)

Reality (release-canonical): the minimal cross-bank conservation transition
is ~7.56M PVM steps ≈ 76 canonical segments; ~26–29 GB peak per segment,
~22 min chain-prove, ~55 min full real-STARK e2e on a 62 GB box. Receiving
side is cheap: streaming verify fetches+verifies+drops one ~3 MiB segment at
a time (phone-class). So **live synchronous proving is not demo-viable** —
the showcase uses `Mode::Signature` live + one precomputed/async real STARK
verified cross-node. The succinct-merkle witness is the transition proof
(batch-sized touched-leaf + Merkle-path witness against the pre-state root,
not ledger-sized). RAM levers (unstarted): SideNote diet (~10× trace RAM),
the streaming prover (chunked column commit within a segment). Native
recursive aggregation is dead (measured intractable; archived); the
streaming prover is the live direction and the natural fit to
refine+accumulate (prove off the hot path, per settlement window not per
transfer).
