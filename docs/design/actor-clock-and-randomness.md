# Deterministic clock & verifiable randomness for VOS actors

**Status:** design agreed 2026-06-15 (branch `messaging`); not yet implemented.
**Supersedes:** the "host round-driver / messenger-tick driver" sketch in the P3
section of [`messaging-pvm-native.md`](./messaging-pvm-native.md). That doc's
`beacon` actor is the seed of the **chronos** service described here.

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

This document defines how both reach a deterministic actor **without breaking
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

### State & API (evolution of `actors/beacon/src/lib.rs`)

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

### The feed (F1 — agreed)

The **raft leader feeds chronos at the sequencing boundary** via
`node.invoke(chronos_id, advance(slot, entropy))` with **`Caller::System`**
(`vos/src/node.rs` `invoke_with_timeout` ~2707; System bypasses the role gate via
`Caller::is_trusted`, `vos/src/actors/auth.rs` ~235 / `context.rs` `has_role`
~170). No leadership detection: raft serializes, and on a follower the local
replica's write fails NotLeader so `node.invoke` returns `None` benignly — only
the leader's advance lands. This is the **one** minimal, generic, runtime-layer
touch; it is not messaging/app code and not the messenger extension. (The rejected
alternative — a faucet *extension* on a `tick` — relays Unauthenticated and so
cannot drive a gated `advance` without making it dangerously open.)

The driver reuses the existing vosx daemon periodic hook
(`run_forever_with` → `reconcile_installed_agents`, `vosx/src/commands/space/up.rs`
~226) as a sibling pass: resolve `instance_service_id("chronos", prefix)`, skip if
`!node.has_agent(id)`, `init` once (idempotent), then each pass compute
`slot = floor(wall_ms / SLOT_MS)` and `entropy = getrandom(32)` and invoke
`advance`. `getrandom` failure → skip the pass (never feed zero entropy).

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

- **Slot = 250 ms** (default, configurable) — 4 Hz, fine enough for ordering /
  presence / expiries. Integer slots from a fixed **VOS Common Era** anchor, so
  the JAM structure (slot, epoch) is preserved, just faster. (Tune 100 ms–1 s.)
- **Entropy round = coarse** (default ~1 s, i.e. one finalized round per epoch of
  N slots, or per real commit). Randomness does **not** need 4 Hz, and the future
  VRF/committee work is the expensive part — keep its rate low.

**Cost note (tune + benchmark):** every `advance` that changes state is a raft
commit. Feeding the *clock* at 4 Hz = 4 commits/s/space, which is heavy for a chat
app. Mitigations, in order: (a) **piggyback** the slot stamp on raft traffic that
is already happening (msg-ctl commits carry the current slot for free), so a
dedicated clock advance fires only as an **idle keepalive**; (b) fold entropy only
on epoch boundaries (cheap blake2b, bounded history); (c) keep chronos state small.
The clock's freshness is bounded by the advance cadence — pick the keepalive
interval to match the protocol's real-time needs.

## Crypto evolution (behind the stable API)

- **v0 (now): blake2b hash-chain, trusted leader.** `beaconₙ = H(domain ‖ prevₙ₋₁
  ‖ n ‖ entropyₙ)`. Already built. The leader could grind; documented v0 trust
  boundary. Add `latest_final()` (lagged read) — the single highest-value upgrade.
- **v1: Ristretto ECVRF + commit-reveal across raft voters.** Each round folds a
  VRF output over `(prev, epoch)` so the value is unpredictable-yet-verifiable and
  one honest voter randomizes it; commit-reveal kills the leader's 1-bit
  withholding bias. Reuses the Ristretto/Ed25519 primitives present in zkpvm.
- **v2 (JAM interop): Bandersnatch RingVRF** — the true "play nice with JAM"
  endpoint (`η₀' = blake(η₀ ‖ VRF_out)`), a precompile lift.

We adopt **drand's architecture** (a known committee = the raft voters produces;
everyone else pulls; verifiable) but **not its crypto** — threshold-BLS needs a
pairing precompile VOS does not have (decision carried from
[`messaging-pvm-native.md`](./messaging-pvm-native.md)).

## Security invariants (must hold at every version)

1. **The beacon is never key material.** It enters a key derivation only as HKDF
   `info` on the output branch, bound to `(space_id, epoch, domain)`; confidentiality
   rests on the secret seed alone (RFC 9180 §9.7.5). The messenger consume seam is
   already shaped for this: `host_rand.rs` `set_beacon`/`PublicBeacon` (~78, ~173)
   feed only the output-branch `info` — drop the `#[allow(dead_code)]` when wiring.
2. **Grinding-sensitive consumers read the lagged value**, never the live head.
3. **Time is bounded, not trusted:** strict monotonicity + a future-drift cap on
   the stamped slot.
4. **Clock/entropy never originate in actor or messaging code** — only the
   runtime feeder (the raft leader) samples wall-clock/`getrandom`.

## Reused primitives (the "reuse if it fits" audit)

- `actors/beacon` → generalized in place into `chronos` (chain, history,
  `verify_chain`, role gate).
- **raft** consistency + leader-forward (chronos is raft; the leader is the feeder).
- **effect log** (`vos/src/effect_log.rs`) — deterministic consumer replay, no new
  machinery.
- **`VosNode::invoke`** `Caller::System` path (`node.rs` ~2707) — the feed call.
- vosx **`run_forever_with`** periodic hook (`up.rs` ~226) + `instance_service_id`
  / `has_agent` — the feed driver, no new host loop.
- **blake2b** precompile (v0); **Ristretto/Ed25519** zkpvm precompiles (v1).
- messenger **`set_beacon`/`PublicBeacon`** seam (`host_rand.rs`) — the hedge
  consume site, already built and dead-code-gated.
- `examples/agents/scheduler` self-tick / `lifecycle::invoke` pattern — reference
  for any future actor-driven cadence.

## Phased implementation plan

- **Phase A — generalize `beacon` → `chronos` (self-contained, no host changes).**
  Add `current_slot`/`now()`, `advance(slot, entropy)` (was `advance(entropy)`),
  `latest_final()`/`randomness_at(epoch)` (lagged read), epoch derivation, the
  finalized-vs-live split. Keep `verify_chain`, history bound, role gate. Unit-test
  in its own `[workspace]` with the noop-waker `run()` (no `vos::block_on`).
  `just build-beacon` (rename target/crate as desired).
- **Phase B — the leader `Caller::System` feed.** Sibling pass in the vosx daemon
  periodic hook: resolve local chronos, init once, stamp `slot` + fold `entropy`
  via `node.invoke`. Separate (fast) cadence gate from the ~2 s reconcile gate;
  piggyback/idle-keepalive per the cost note. Followers' `None` is benign.
- **Phase C — consumer wiring = the original P3 hedge.** Messenger reads
  `chronos.latest_final()` → `set_beacon` (lagged, domain-bound); drop the
  `#[allow(dead_code)]` on `set_beacon`/`PublicBeacon`; unit test (beacon set ⇒
  output differs, ratchet state identical); confirm the determinism gate +
  `two_nodes_exchange_e2ee_messages` + `retry` stay green (absent chronos ⇒ `None`
  ⇒ no hedge ⇒ no behavior change). Install `chronos` (raft) in
  `examples/space-msg-{a,b}.toml`. Optionally replace caller-supplied `ts_ms` with
  `chronos.now()`.
- **Phase D (later) — bias resistance.** v1 Ristretto ECVRF + commit-reveal; then
  v2 Bandersnatch for JAM interop. **Scoped:**
  [`chronos-bias-resistance.md`](./chronos-bias-resistance.md) — the
  `actors/_chronos_crypto_spike` fixture proves pure-software
  ECVRF-RISTRETTO255 (prove/verify + committee XOR-combine) compiles,
  transpiles, and runs correctly on the PVM, so the precompile is a *performance*
  follow-on, not a correctness gate (the ristretto ECALLs 110-114 already exist
  on the proving side). The doc covers the committee commit-reveal protocol, the
  v0→v1 seam (behind the unchanged API), and the honest residual 1-bit
  last-revealer bound.

## Open questions / tunables

- **Slot length & epoch size** — default 250 ms slot, ~1 s entropy epoch; benchmark
  the raft-commit cost and the piggyback/keepalive split.
- **Global VOS Common Era vs per-space genesis** — global is more JAM-faithful and
  gives cross-space-comparable slots; per-space is simpler/isolated. Default:
  global era, per-space domain tag on the entropy.
- **Name** — `chronos` vs `oracle` vs keep `beacon`; whether clock + entropy are
  one actor or two (one is simpler — shared feed/boundary).
- **rkyv state versioning** — chronos adds fields to the beacon's whole-struct
  rkyv state (no version tag today): treat the add as a deliberate re-init or add
  a version byte, per the beacon module's existing caveat.
