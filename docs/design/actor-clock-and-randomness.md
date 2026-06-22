# Deterministic clock & verifiable randomness for VOS actors

The **chronos** service gives deterministic VOS actors a clock and verifiable randomness:
a v0 clock + blake2b entropy chain and v1 Ristretto ECVRF committee bias resistance, with
the messenger hedge that consumes it. See also the verifiable-randomness section of
[`messaging-pvm-native.md`](./messaging-pvm-native.md); chronos is the generalization of
that doc's `beacon` actor.

## Why

VOS actors are deterministic by construction — a PVM agent's only hostcalls are
gas / fetch / preimage / storage / info / grow-heap / debug / invoke
(`vos/src/abi/hostcall.rs`), and `vos::crypto` exposes blake2b only. There is **no
entropy and no wall clock** inside an actor; every `ts_ms` in the system today is a
*caller-supplied argument* (e.g. `actors/msg-log/src/lib.rs` `post`), and the
`beacon` cannot be advanced from a periodic extension `tick` because a tick relays
`Caller::Unauthenticated` (`vos/src/node.rs` ~4018, `resolve_relay_caller` ~4320),
which fails any role-gated mutating handler.

But the messaging / collaboration protocols need both:

- a **clock** — message ordering, MLS epoch lifetimes, presence/freshness,
  expiries — at real-time-ish (sub-second) resolution; and
- **verifiable randomness** — fair ordering/sampling, domain separation, and an
  optional HKDF-`info` hedge for the MLS CSPRNG.

This document records how both reach a deterministic actor **without breaking
determinism** and **without putting time/randomness origination into application
code or a native extension**, while staying close to JAM so a future JAM
integration plays nice.

## The principle (validated against JAM + the major chains)

Every blockchain resolves nondeterminism the same way, and we adopt it verbatim:

> The raw nondeterministic input (wall-clock, fresh randomness) is **sampled once
> by a single proposer at a sequencing boundary, committed to the agreed
> log/state, and replayed identically by everyone**. The wall-clock is used only
> as an *acceptance bound*, never as a value fed into execution.

JAM (Gray Paper v0.8.0) is explicit:

- **Time** is an integer timeslot `τ`. The block author writes `H_t` into the
  signed header; state does `τ' ≡ H_t` (a pure copy). Validity requires
  `parent_t < H_t ≤ w/6` where `w` is the validator's local wall-clock — so the
  clock only *gates acceptance*; the value executed with is the header integer.
- **Entropy** is a 4-slot buffer `η₀..η₃` with `η₀' = blake(η₀ ‖ VRF_out(seal))`
  (a Bandersnatch RingVRF output — unsteerable, verifiable). Buffers rotate per
  epoch, and **grinding-sensitive consumers read a lagged buffer (η₂), never the
  live η₀**, because η₀ is biasable by block-withholding.
- **Accumulate** (stateful, in-consensus) is handed `τ` and can `fetch` `η₀`;
  **refine** (stateless, parallel, re-auditable) is denied both (its entropy slot
  is hard-wired to zero). *Never sample fresh time/randomness in the
  parallel/replayable phase — only read pinned, committed values.*

The major chains converge on three rules we treat as constraints:

1. **Sample at the sequencer, commit, replay.** (Eth `block.timestamp`,
   Tendermint BFT-time, JAM `H_t`.)
2. **A lone proposer is a 1-bit last-revealer** (it can withhold/re-propose to
   grind one bit). Bound it: monotonicity + future-cap for time; VRF /
   commit-reveal / lag-before-consume for entropy. drand removes the bit with a
   threshold *unique* signature — at the cost of pairings + DKG.
3. **Pull by index; the value is a function of log position, not wall-clock.**
   Bind each consumer with a domain tag; keep the beacon strictly out of key
   material.

VOS already has both boundaries this needs:

- the **raft leader** = the block-author / proposer analog (it already proposes
  the committed sequence and forwards followers' writes to itself); and
- the **effect log** (`vos/src/effect_log.rs`) = the "pin the observed `ctx.ask`
  reply, replay it" oracle, which already makes CRDT/raft replicas rebuild state
  identically without re-issuing asks.

## The design: chronos — time/randomness as a service

A single well-known per-space **`chronos`** service actor (the generalized
`beacon`) — bundled, present in most spaces like the space-registry — that
**holds** a clock + an entropy accumulator and **serves** them over a stable
pull API. Consumers never originate time/randomness; they ask chronos.

```text
                 feeds (once, at the sequencing boundary)
   raft leader ───────────────────────────────────────────►  chronos (raft actor)
   (Caller::System: node.invoke)   advance(slot, entropy)        • clock: current slot
        ▲ wall-clock + getrandom                                 • entropy: η accumulator
        │                                                        • lagged/finalized read
        │ followers' advance → None (benign; only leader lands)
                                                                      │ ctx.ask (pull)
   any actor (msg-ctl, messenger, …) ◄────────────────────────────────┘
   reply pinned in the consumer's effect log → deterministic replay
```

### State & API (`actors/chronos/src/lib.rs`, generalized from the old `beacon`)

- **Clock:** `current_slot: u64` (+ derived `epoch`). Monotone.
- **Entropy:** the existing blake2b hash-chain of contributed entropy
  (`derive_beacon`, `verify_chain`, bounded `MAX_HISTORY` history) — unchanged
  shape, now keyed by *epoch/round*.
- **Reads (public, ungated — reachable as Unauthenticated, which is correct for
  public reads):**
  - `now() -> u64` — the current slot.
  - `current() -> Option<Round>` — the live entropy head (η₀ analog; **low-stakes
    use only**).
  - `latest_final() -> Option<Round>` and `randomness_at(epoch) -> Option<Round>`
    — the **lagged/finalized** value (η₂ analog; the read grinding-sensitive
    consumers and the messenger hedge MUST use).
  - `range(from, limit)` / `verify_chain` — already present, for auditing.
- **Writes (gated to the feeder; `Caller::System`/leader passes the gate):**
  - `advance(slot, entropy)` — stamp the slot (bounded: `slot > current_slot`)
    and, on an epoch boundary, fold `entropy` into a new finalized round.

The API is the stable seam. Everything behind it — hash-chain → VRF → committee —
evolves without touching a single consumer.

### The feed

The **raft leader feeds chronos at the sequencing boundary** via
`node.invoke(chronos_id, advance(slot, entropy))` with **`Caller::System`**
(`vos/src/node.rs` `invoke_with_timeout`; System bypasses the role gate via
`Caller::is_trusted`, `vos/src/actors/auth.rs` / `context.rs` `has_role`). No
leadership detection: raft serializes, and on a follower the local replica's write
fails NotLeader so `node.invoke` returns `None` benignly — only the leader's
advance lands. This is the **one** minimal, generic, runtime-layer touch; it is
not messaging/app code and not in the messenger. (The rejected alternative — a
faucet *extension* on a `tick` — relays Unauthenticated and so cannot drive a
gated `advance` without making it dangerously open.)

The driver (`ChronosFeeder`, `vosx/src/commands/space/up.rs`) is a sibling pass on
the existing vosx daemon periodic hook (`run_forever_with`): it resolves the local
chronos via `instance_service_id`/`has_agent`, `init`s once (idempotent), then on
its own keepalive cadence (`CHRONOS_FEED_EVERY`, 1 s — deliberately *not* the slot
rate) computes `slot = (wall_ms - VOS_COMMON_ERA_MS) / CHRONOS_SLOT_MS` and
`entropy = getrandom(32)` and invokes `advance`. `getrandom` failure → skip the
pass (never feed zero entropy). On a voter the same pass also mirrors the
registry's `NODE_ROLE_VOTER` set into chronos (`set_committee`) and drives the v1
committee commit-reveal locally over `Caller::System` — no extra network, no extra
block beyond the keepalive advance.

### Determinism for consumers

A consumer reads chronos with `ctx.ask` (a synchronous INVOKE hostcall;
`vos/src/actors/context.rs` ~309). The reply is **pinned in the consumer's effect
log**, so its replay across replicas and restarts is identical regardless of when
it asked — exactly like every tx in an Eth block seeing the same `block.timestamp`.
Following JAM's refine/accumulate rule: consumers treat chronos values as **pinned
inputs read in the committing path**, never as fresh samples; grinding-sensitive
logic reads `latest_final()`/`randomness_at(epoch)` (lagged), never `current()`.

CRDT actors with no sequencer keep using logical/lamport time for their own
ordering and bind cross-actor coordination to a chronos epoch number; they read
chronos through the same pinned-`ctx.ask` path.

## Cadence: a fast clock, coarse entropy rounds

This is the "real-time-ish" decision and VOS's deliberate divergence from JAM.

- **Slot = 250 ms** (`CHRONOS_SLOT_MS`) — 4 Hz, fine enough for ordering /
  presence / expiries. Integer slots from a fixed **VOS Common Era** anchor
  (`VOS_COMMON_ERA_MS`), so the JAM structure (slot, epoch) is preserved, just
  faster.
- **Entropy round = coarse** (`SLOTS_PER_EPOCH = 4` slots ≈ 1 s per folded round,
  folded at most once per epoch boundary). Randomness does **not** need 4 Hz, and
  the VRF/committee work is the expensive part — its rate stays low.

**Cost note:** every `advance` that changes state is a raft commit. Feeding the
*clock* at the full 4 Hz slot rate would be 4 commits/s/space, heavy for a chat
app. The mitigations: (a) the feeder advances on an **idle keepalive** cadence
(`CHRONOS_FEED_EVERY = 1 s`), *not* the 250 ms slot rate; (b) entropy folds only
on epoch boundaries (cheap blake2b, bounded history); (c) chronos state is kept
small (bounded round history). The clock's freshness is bounded by the keepalive
cadence. **Open follow-on:** benchmark the raft-commit cost and add the
**piggyback** optimisation — stamp the current slot onto raft traffic that is
already happening (e.g. msg-ctl commits carry the slot for free), so a dedicated
clock advance fires only when the space is otherwise idle.

## Crypto evolution (behind the stable API)

- **v0: blake2b hash-chain, trusted leader.** `beaconₙ = H(domain ‖ prevₙ₋₁ ‖ n ‖
  entropyₙ)`. The leader can grind; this is the documented v0 trust boundary.
  `latest_final()` (lagged read) is the single highest-value hardening. A
  committee-less round folds immediately on the leader entropy (so absent a
  committee, behaviour is exactly v0).
- **v1: Ristretto ECVRF + commit-reveal across raft voters.** Each round folds VRF
  outputs over a public `α` so the value is unpredictable-yet-verifiable and one
  honest voter randomizes it; the reveal window (`REVEAL_WINDOW_EPOCHS`) kills the
  leader's 1-bit withholding bias. Reuses the Ristretto/Ed25519 primitives present
  in zkpvm; the ECVRF ciphersuite hash is **SHA-512** (ECVRF-RISTRETTO255-SHA512),
  not blake2b. See the `vrf` crate + the committee combine (`combine_betas`,
  `verify_round`) and `chronos-bias-resistance.md`.
- **v2 (future, JAM interop): Bandersnatch RingVRF** — the true "play nice with
  JAM" endpoint (`η₀' = blake(η₀ ‖ VRF_out)`), a precompile lift.

We adopt **drand's architecture** (a known committee = the raft voters produces;
everyone else pulls; verifiable) but **not its crypto** — threshold-BLS needs a
pairing precompile VOS does not have (decision carried from
[`messaging-pvm-native.md`](./messaging-pvm-native.md)).

## Security invariants (must hold at every version)

1. **The beacon is never key material.** It enters a key derivation only as HKDF
   `info` on the output branch, bound to its round via blake2b; confidentiality
   rests on the secret seed alone (RFC 9180 §9.7.5). The messenger's
   `host_rand.rs` `set_beacon`/`PublicBeacon` feed only the output-branch `info`,
   never seed/salt/ratchet; `mls::build_client_hedged` folds the beacon there and
   nowhere else.
2. **Grinding-sensitive consumers read the lagged value**, never the live head.
3. **Time is bounded, not trusted:** strict monotonicity + a future-drift cap on
   the stamped slot.
4. **Clock/entropy never originate in actor or messaging code** — only the
   runtime feeder (the raft leader) samples wall-clock/`getrandom`.

## Reused primitives (the "reuse if it fits" audit)

- `actors/beacon` → generalized into `actors/chronos` (chain, history,
  `verify_chain`, role gate).
- **raft** consistency + leader-forward (chronos is raft; the leader is the feeder).
- **effect log** (`vos/src/effect_log.rs`) — deterministic consumer replay, no new
  machinery.
- **`VosNode::invoke`** `Caller::System` path (`node.rs`) — the feed call.
- vosx **`run_forever_with`** periodic hook (`up.rs`) + `instance_service_id`
  / `has_agent` — the feed driver (`ChronosFeeder`), no new host loop.
- **blake2b** precompile (v0); **Ristretto/Ed25519** zkpvm precompiles (v1).
- messenger **`set_beacon`/`PublicBeacon`** seam (`host_rand.rs`) — the hedge
  consume site, wired via `mls::build_client_hedged` ← `clients::chronos_beacon`.
- `examples/agents/scheduler` self-tick / `lifecycle::invoke` pattern — reference
  for any future actor-driven cadence.

## Implementation

- **`actors/chronos`** (the generalization of the `beacon` actor): `current_slot`/
  `now()`, `advance(slot, entropy)`, `latest_final()`/`randomness_at(epoch)`
  (lagged), epoch derivation, finalized-vs-live split; `verify_chain`, history
  bound, role gate.
- **The leader `Caller::System` feed.** `ChronosFeeder` is a sibling pass in the
  vosx daemon periodic hook: it resolves the local chronos, `init`s once, and
  stamps `slot` + folds `entropy` via `node.invoke` on its own keepalive cadence
  (separate from the reconcile gate). Followers' `None` is benign.
- **Consumer wiring (the messenger hedge).** The messenger reads
  `chronos.latest_final()` (`clients::chronos_beacon`) → folds it (domain-bound by
  blake2b to its round) into the MLS CSPRNG HKDF output branch only via
  `mls::build_client_hedged` → `set_beacon`. The five key-minting handlers
  (key_package/create/send/stock_directory/commit_chain_op) fetch the beacon;
  absent chronos ⇒ `None` ⇒ byte-identical to before.
- **Bias resistance.** v1 Ristretto ECVRF + committee commit-reveal (committee
  XOR-combine over a reveal window; ECVRF-RISTRETTO255-SHA512), scoped in
  [`chronos-bias-resistance.md`](./chronos-bias-resistance.md) — the committee
  commit-reveal protocol, the v0→v1 seam (behind the unchanged API), and the honest
  residual 1-bit last-revealer bound. Pure-software ECVRF compiles, transpiles, and
  runs on the PVM (`chronos_transpile.rs` over the real `chronos.elf`), so the
  precompile lift is a *performance* follow-on, not a correctness gate. **v2
  Bandersnatch RingVRF** for true JAM interop is the open future endpoint
  (precompile-gated).

## Settled decisions

- **Slot length & epoch size** — shipped as constants: `CHRONOS_SLOT_MS = 250`
  (slot, `vosx/.../up.rs`), `SLOTS_PER_EPOCH = 4` (≈ 1 s entropy epoch,
  `actors/chronos/src/lib.rs`), `FINALIZED_LAG = 2` (the η₂ lag),
  `REVEAL_WINDOW_EPOCHS = 2` (v1 committee window).
- **Global VOS Common Era vs per-space genesis** — chose the **global era**
  (`VOS_COMMON_ERA_MS`, more JAM-faithful, cross-space-comparable slots) with a
  per-space domain tag on the entropy.
- **Name & shape** — chose `chronos`, with clock + entropy as **one actor**
  (simpler — shared feed/boundary).
- **rkyv state versioning** — chronos adds fields over the beacon's whole-struct
  rkyv state as a **deliberate re-init** (the layout caveat in the module doc
  applies to any future field add too, e.g. the v2 RingVRF fields).

## Open items / follow-ons

- **v2 Bandersnatch RingVRF** (future) — the true JAM-interop endpoint
  (`η₀' = blake(η₀ ‖ VRF_out)`); precompile-gated (see the bias-resistance section
  and `chronos-bias-resistance.md`).
- **Slot/epoch benchmark + piggyback optimisation** — benchmark the raft-commit
  cost of the keepalive cadence and add the piggyback path (stamp the slot onto
  raft traffic already happening; dedicated advance only when idle), per the cost
  note above.
