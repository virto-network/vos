# Chronos bias resistance — ECVRF + committee commit-reveal (Phase D)

**Status:** **v1 LANDED 2026-06-16, branch `messaging`** (D0–D4 + two fixes;
commits `37876d6`→`76c3aec`). The design below is the original groundwork; read
the **As-built** section next for where the implementation diverged.
**Extends:** [`actor-clock-and-randomness.md`](./actor-clock-and-randomness.md)
(the "Crypto evolution" + "Security invariants" sections). Phases A/B/C of that
doc are landed; this is its Phase D ("bias resistance").

## As-built (Phase D v1 landed)

The committee protocol matches the design — per-voter ECVRF over `α`, XOR
combine, multi-epoch open→reveal→fold, the lagged read, the unchanged pull API —
with three deltas worth recording, plus two bugs found and fixed during
verification:

- **Auth is cryptographic, not caller-based (delta from §Seam evolution).** The
  design assumed a follower's reveal/enrol arrives as `Caller::Peer`. It does at
  the libp2p edge, but a chronos handler runs on the **raft apply path, where the
  originating caller is NOT preserved** — a cross-node reveal reaches the handler
  as `Caller::Unauthenticated`. So `reveal(voter_id, round, proof)` authenticates
  by the VRF proof itself (verified against the round's snapshot key — only the
  key holder could produce it), and `enrol_voter(voter_id, pubkey)` by the
  leader-pushed authorized set + **first-wins** binding (rebinding a different key
  → `STATUS_KEY_LOCKED`). General lesson: *authenticate a raft actor's writes by
  what's in the committed entry (a signature/proof), never by the caller.*
- **Enrol residual (documented).** Because enrol is caller-free, a party that
  front-runs an authorized voter's *first* enrol can bind its own key to that
  slot (committee griefing/Sybil within the authorized set). No β is ever
  forgeable, so bias resistance is intact. The proper close is binding the VRF
  pubkey in the **registry at admit time** (the rejected "option B" — now the
  recommended hardening; see the roadmap).
- **Runtime prerequisite found + fixed (`654b2da`).** A raft agent soft-restarted
  (reload + replay the whole DAG) on *every* committed index — including the echo
  of its own proposals — so a continuously-committing actor (the chronos clock,
  the first such consumer) thrashed O(n²) and transiently reset to genesis. This
  was a **pre-existing** runtime bug (reproduced on v0 chronos), not Phase D's.
  Fix: `CommitStrategy::needs_sync_reload()` gates the restart on whether the
  store actually moved ahead of what the agent applied (`commit_index >
  last_applied` for raft) — reload only for genuine remote merges, never for the
  agent's own commits.
- **Verified live:** 38 chronos unit tests; vos lib 267; messenger e2e + retry;
  a 2-node committee folding both voters' VRF reveals every round on the PVM; and
  the full `just demo-msg-procs` (messenger + chronos) green.
- **Done:** D0 (`vrf`), D1 (enrol substrate), D2 (round protocol), D3
  (`verify_combine`), D4 (vosx feeder). **Deferred:** D5 (ristretto precompiles —
  perf, gated on profiling) and D6 (Bandersnatch RingVRF, JAM interop).
- **Open follow-ups (persisted in the roadmap):** a committed multi-node
  committee integration test (the live path is only script/demo-verified today);
  registry pubkey-binding to close the enrol residual; and incremental
  follower-apply (a raft follower still full-replays per applied entry — perf,
  not correctness).

## Why

v0 chronos is a blake2b hash-chain of leader-contributed entropy: the round
driver supplies the 32 bytes folded each epoch and could **grind** it (try
values, pick a favourable beacon) before committing. v0 documents this as the
trusted-leader boundary. Phase D removes the grind by making each round's
entropy a **verifiable random function (VRF) output** that no one can choose,
contributed by a committee (the raft voters) under commit-reveal so a single
honest voter randomises the round. This is the v1 step toward JAM's entropy
model; v2 swaps in Bandersnatch RingVRF for true JAM interop.

The whole upgrade lives **behind the stable pull API** (`now`/`epoch`/
`current`/`latest_final`/`randomness_at`/`range`/`verify_chain`): no consumer
changes — the messenger hedge and every other reader keep working unmodified.

## Feasibility verdict: the precompile is NOT a correctness gate

The v0 module doc said the ECVRF upgrade was "gated on the edwards/ristretto
precompiles being wired into `vos::crypto`." **Groundwork finding: it is not** —
exactly as the P2 spike found for the messenger ciphersuite.

A feasibility fixture, `actors/_chronos_crypto_spike` (mirroring
`actors/_crypto_spike`), implements a minimal **ECVRF-RISTRETTO255-SHA512**
(keygen / prove / verify) plus the committee XOR-combine in pure no_std
software over `curve25519-dalek` (serial backend) + SHA-512, and:

- **compiles + transpiles** (`grey_transpiler::link_elf`) to a riscv64em-javm
  PVM ELF (202 KB), using only the blake2b precompile; and
- **runs correctly on the PVM** — `vosx run` instantiates the actor, `new()`
  round-trips a valid proof (verify ⇒ true) and rejects a tampered proof, a
  wrong key, and a wrong input (verify ⇒ false), asserts the 80-byte wire
  encoding, and asserts the XOR-combine is order-independent. A flip test (one
  assertion inverted) panics on the PVM at the exact line, proving the checks
  execute rather than merely link.

`curve25519-dalek` 4.1.3 (the version `ed25519-dalek` v2 already pulls and the
P2 spike already transpiled) ships the `ristretto` module **unconditionally** —
`RistrettoPoint`, `CompressedRistretto`, `from_uniform_bytes` (Elligator
hash-to-curve), `Scalar * RistrettoPoint`, scalar arithmetic — with
`default-features = false`. No `rand_core` ⇒ no `::random` ⇒ determinism is
structurally enforced (every scalar is loaded from bytes). The `+e`
16→13-register squeeze is a non-issue (same as P2).

So ECVRF verify decomposes into operations that **all run in software today**:
hash-to-curve (Elligator), two scalar-mults (`s·B`, `c·pk` / `c·Γ`), and a
scalar negation. There is no point/scalar-negate ECALL, but negation is free in
software (`-c`); the precompile path would fold it as `c·(L−1) mod L`. No
pairings anywhere (that is why drand's *crypto* stays ruled out — see below).

### The precompiles are a measured performance follow-on

The ristretto precompiles already exist on the proving side and are
**pre-allocated but unhandled** for actors:

- `zkpvm/src/core/ecall.rs` defines `ECALL_RISTRETTO_SCALAR_MULT` (110),
  `RISTRETTO_POINT_ADD` (111), `SCALAR_FROM_BYTES_MOD_ORDER_WIDE` (112),
  `SCALAR_MUL_MOD_L` (113), `SCALAR_ADD_MOD_L` (114), with guest shims in
  `zkpvm/precompiles/` and host tracing impls in `zkpvm/src/core/tracing.rs`.
- `vos/src/runtime.rs` `install_vos_precompile_caps` (~159-180) installs cap
  slots 100 + 110-114 into every actor, but `handle_refine_hostcall`
  (~1074-1115) has a match arm only for blake2b (100); 110-114 hit the default
  `_ => HOST_WHAT` (fail). The R1e scalar-mult chip is complete (~6500 rows/op,
  ~0.75 ms CPU per the chip DESIGN.md).

Wiring a precompile = the blake2b template (`vos/src/crypto/blake2b.rs` +
the `runtime.rs` handler): ~6 files, ~100 LOC per primitive (a new
`vos/src/crypto/ristretto.rs` host impl + a `runtime.rs` match arm; the cap
slots and guest shims already exist). The **dominant un-accelerated cost is
hash-to-curve** (Elligator over a SHA-512/blake2b expansion) — not yet an ECALL;
reserve `ECALL_HASH_TO_RISTRETTO` (e.g. 115) and add it only if profiling the
actual chronos round shows the software path bites. Correctness never depends on
any of this.

## v1 design — ECVRF-RISTRETTO255 + committee commit-reveal

### Per-voter VRF (kills the grind)

Each raft voter `i` holds a VRF keypair `(sk_i, pk_i)` over Ristretto255. Each
round's contribution is `β_i = VRF_prove(sk_i, α)` where the input
`α = blake2b(prev_beacon ‖ epoch)` is public and fixed. Because `β_i` is a
**deterministic** function of the voter's fixed secret and the public input, a
voter cannot grind their own contribution (no "try many values") — the only
freedom left is the binary choice to reveal or withhold (the last-revealer bit,
addressed below). Others cannot predict `β_i` before reveal (the VRF secret-key
property), and anyone can verify it afterward with `pk_i` and the 80-byte proof.

**Proof shape (RFC 9381, ECVRF-RISTRETTO255-SHA512):** `Γ ‖ c ‖ s` = 32 + 16 +
32 = **80 bytes**. `Γ = sk·H`, `c = challenge(pk,H,Γ,k·B,k·H)` (128-bit), `s =
k + c·sk`; verify recomputes `U = s·B − c·pk`, `V = s·H − c·Γ`, accepts iff the
re-derived challenge equals `c`; the VRF output is `β = H(Γ)`. The spike
implements exactly this. (SHA-512 keeps drand/Sui interop; a blake2b
substitution is sound but non-standard — decide at build time.)

### Committee combine (one honest voter randomises the round)

The round's entropy is the **XOR (or hash) of all revealed `β_i`**. XOR is
order-independent and a single honest, unpredictable `β_i` randomises the whole
combine, so the round is unbiased as long as ≥1 voter is honest. The combined
value folds into the existing chain exactly as v0 folds `entropy`:
`beaconₙ = H(domain ‖ prevₙ₋₁ ‖ n ‖ slotₙ ‖ combined_βₙ)` — the v0
`derive_beacon` is unchanged; only the *source* of the folded bytes changes.

This is **drand's architecture** (a known committee = the raft voters produces;
everyone else pulls by round; verifiable) without **drand's crypto**
(threshold-BLS needs a pairing on BLS12-381, and VOS has no pairing precompile).

### Round timeline (leader never blocks on voters)

`advance` cannot block on slow voters, so the round is a multi-epoch async
protocol layered on the existing leader feed:

1. **Commit** (epoch *N* boundary): the leader's `advance` opens round *N* and
   records the public input `α = blake2b(prev ‖ N)`. (Optionally each voter
   commits `H(β_i)` here to bind the reveal.)
2. **Reveal** (epochs *N*+1 …): each voter asynchronously calls a new
   `reveal(round, β_i, proof_i)` handler (a raft write, so it is sequenced and
   carries the voter's authority). chronos verifies `proof_i` against `pk_i` and
   accumulates valid reveals.
3. **Fold** (all-revealed or timeout at epoch *N*+k): combine the collected
   `β_i`, fold into `beacon_N`, and the round becomes part of the chain.
4. **Read**: consumers read `latest_final()` / `randomness_at(epoch)` — already
   lagged by `FINALIZED_LAG`, so in-flight reveals never leak into a consumed
   value.

The lag the v0 actor already enforces (η₂) is what makes the async reveal window
safe: a value is only ever consumed once its round is finalized, well after its
reveals settled.

## Security analysis — what v1 fixes and the residual 1-bit leak

**Fixed:** the leader can no longer grind the round's entropy. In v0 the leader
chooses 32 arbitrary bytes and can hash-search for a favourable beacon. In v1
the entropy is `XOR(β_i)` of deterministic VRF outputs — no party can choose
their `β_i`, so the unbounded grind is gone.

**Residual (honest):** commit-reveal without threshold crypto leaves a **1-bit
last-revealer** bias. Whoever reveals last sees the other reveals, can compute
the would-be combined value *with* vs *without* their (fixed) contribution, and
choose to reveal or withhold — selecting between two outcomes. This is the same
bound JAM names; it is *bounded* (1 bit, not arbitrary) and further blunted by
(a) the lagged read, (b) requiring a reveal window short enough that withholding
is detectable/penalised, and (c) the fact that ≥1 honest revealer makes the
result unpredictable to everyone until the fold. Fully removing the bit needs
either a threshold signature (pairings — ruled out) or a delay function / VDF
binding the commit before any reveal is seen — both are post-v1. v1 is a strict
improvement over v0's full-grind, not a perfect beacon; grinding-sensitive
consumers keep reading the lagged value, never the live head (invariant 2,
unchanged).

The four security invariants from the parent doc are preserved: the beacon
stays HKDF-`info`-only (never key material); grinding-sensitive consumers read
the lagged value; time stays bounded; and clock/entropy still originate only in
the runtime feeder — the VRF *keys* are the voters', the VRF *inputs* are public
chain state, and chronos itself still samples no entropy.

## Seam evolution (v0 → v1, API unchanged)

Anchors are against the landed `actors/chronos/src/lib.rs`.

- **State (`Chronos` struct):** add `voter_pubkeys: BTreeMap<[u8;32],[u8;32]>`
  (voter id → VRF pk, refreshed from the registry on membership change),
  `pending: BTreeMap<u64, RoundDraft>` (round → collected reveals/commitments).
  `BeaconRound` gains `combined: [u8;32]` provenance and an optional
  per-round proof set for `verify_chain`. The rkyv whole-struct state has no
  version tag, so this field-add is a **deliberate re-init** (as the v0→chronos
  field-add already was) or carries an explicit version byte — documented in the
  module, same caveat the slot-add already follows.
- **Handlers:** keep `advance(slot, entropy)` as the leader feed (it now opens a
  round + records `α`); add `reveal(round, beta, proof)` (Advancer/voter-gated,
  a raft write). `init`/reads unchanged. `AdvanceOutcome` shape unchanged.
- **Voter keys:** the voter set is the registry's `MemberRow`s with
  `kind == MEMBER_KIND_NODE && role == NODE_ROLE_VOTER`
  (`actors/space-registry`); each voter's VRF pk is enrolled alongside (a new
  registry field or a chronos-local enrol handler). chronos caches it like the
  feeder caches the chronos replication id.
- **`verify_chain`:** extends from "re-hash + linkage" to additionally verify
  each round's VRF proof set against the round's voter pubkeys. Routes through
  the ristretto precompile when wired, software otherwise — identical result.
- **Consumers:** **no change.** `latest_final`/`randomness_at` return the same
  `BeaconRound`; readers never parse proofs or voter keys.

## v2 — Bandersnatch RingVRF (JAM interop, deferred)

JAM's entropy is `η₀' = blake(η₀ ‖ VRF_out(seal))` over **Bandersnatch
RingVRF** — a ring-VRF on a SNARK-friendly curve, letting any ring member
produce a verifiable output without threshold machinery (and hiding *which*
member). It is the true "play nice with JAM" endpoint. A VOS integration needs a
Bandersnatch point/scalar precompile + hash-to-curve + the ring-proof verifier —
a precompile lift comparable in scope to the ristretto chip. Deferred until JAM
interop is a concrete requirement; the v1 ECVRF endpoint serves bias resistance
in the meantime, and the stable API means v2 is again a behind-the-seam swap.

## Phased plan for the v1 build (when scheduled)

- **D0 — VRF library — DONE** (`vrf` crate): the spike's ECVRF lifted into a
  standalone no_std library — `prove`/`verify`/`output` + an 80-byte `Proof`
  codec + `keypair_from_seed`, ECVRF-RISTRETTO255-SHA512, 9 property tests,
  compiles for the PVM target (so the chronos actor can depend on it). Kept out
  of core `vos` (curve25519 only reaches chronos/vosx via this crate). Internal
  ciphersuite — no RFC-registered ristretto suite exists, so correctness rests
  on the algebraic identity + property tests, not cross-impl vectors; SHA-512
  chosen over blake2b (interop-friendlier; revisit only on a profiled win).
- **D1 — voter key enrolment:** registry/chronos plumbing for per-voter VRF
  pubkeys keyed off the existing voter membership.
- **D2 — chronos v1 round protocol:** `advance` opens a round; `reveal` collects
  + verifies; fold on quorum/timeout; the field-add re-init.
- **D3 — `verify_chain` proof verification** + unit tests (valid/forged/missing
  reveals; the 1-bit-leak bound made explicit in a test's comments).
- **D4 — feeder/voter wiring** in vosx: voters post reveals on the chronos feed
  cadence; leader opens rounds (extends the landed `feed_chronos`).
- **D5 (perf, optional):** wire the ristretto precompile handlers (the existing
  ECALLs 110-114) + a hash-to-ristretto ECALL **iff** profiling the round shows
  the software path is the bottleneck — pure performance, gated on measurement.
- **D6 (later):** v2 Bandersnatch precompile + RingVRF for JAM interop.

## Open questions / decisions

- **SHA-512 vs blake2b** in the ciphersuite: SHA-512 keeps drand/Sui interop and
  is proven in the spike; blake2b reuses the existing precompile but is
  non-standard. Lean SHA-512 unless a profiled win says otherwise.
- **Reveal window length / timeout** and the withholding penalty — sets how
  exposed the 1-bit last-revealer bit is in practice.
- **Voter VRF key lifecycle**: per-node static key vs rotating; enrolment venue
  (registry field vs chronos handler); revocation on membership change.
- **Quorum policy**: fold on all-reveals vs a threshold-of-voters vs
  first-k — affects liveness vs the honest-voter assumption.
