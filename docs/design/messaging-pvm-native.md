# PVM-native messaging: deterministic MLS, verifiable randomness, immutable locality, device-sync

The messenger is a **PVM-native actor** — portable RISC-V bytecode, one artifact that runs
everywhere with no platform-specific binary. It runs on mls-rs with a deterministic
host-seeded `CipherSuiteProvider` (bit-identical KeyPackages/commits/Welcomes), builds as a
no_std riscv64 `#[actor]` whose ELF transpiles clean through `link_elf`, and is installed as
a `consistency="local"` PVM `[[agent]]`. This document records the design of that messenger
and its supporting primitives: immutable-local consistency, a host-seeded forward-ratcheting
MLS CSPRNG, the `chronos` verifiable-randomness actor, and a trusted device-sync plane. The
companion bird's-eye index lives in [`messaging-roadmap.md`](./messaging-roadmap.md).

## Why PVM-native

A native cdylib messenger would tie the messenger to a platform-specific binary; a PVM actor
is portable bytecode. The hard constraints for moving MLS into a deterministic PVM are not
`std` itself — they are (1) the deterministic PVM has no entropy and (2) MLS secrets must
never replicate. The work items below dismantle both, plus add two capabilities: a verifiable
space randomness beacon and a trusted multi-device sync plane.

## The randomness model (the load-bearing idea)

Two **separate** randomness planes, kept strictly apart:

- **SECRET randomness = the only confidentiality root.** A per-device secret seed is
  provisioned **once by the host** (real OS entropy) into **non-replicated local state**.
  The actor runs a **forward-ratcheting deterministic CSPRNG** over it. A replayer of the
  replicated msg-log/msg-ctl DAG never holds the seed, so PVM determinism is *not* a
  secrecy leak — this asymmetry is the whole trick. This is sound: neither RFC 9420 (MLS)
  nor RFC 9180 (HPKE) mandates a *non-deterministic* RNG (HPKE `DeriveKeyPair` is
  deterministic by design); RFC 6979 / RFC 8032 / RFC 8937 establish "deterministic from a
  secret" as standard practice. Safety rests on the seed staying secret **and** every draw
  being uniquely contextualized.
- **PUBLIC randomness = operational fairness only.** A per-space verifiable randomness
  actor supplies shared, publicly-verifiable values (fair ordering, sampling, leader
  election, freshness/domain-separation). It is a normal replicated actor.

**The trap to never fall into:** a public beacon is **not** secret entropy. It may be
*hedged in* as a freshness/anti-fault input (`out = HKDF(secret_state, info =
domain‖purpose‖counter‖beacon)`), but security MUST hold on the secret seed alone. If any
path ever lets the beacon substitute for the seed, HPKE confidentiality is "lost
completely" (RFC 9180 §9.7.5). The beacon enters only as HKDF `info`, never as keying
material.

## Work items

### Immutable-local consistency

`Consistency` is a monotone **shareability lattice** and each agent is sealed so its tier
can only ever move toward *more confined*, never widen:

```
Ephemeral (orthogonal, non-persistent)
Local (1) < TrustedDeviceSync (2) < { Crdt (3), Raft (3) }   # Crdt/Raft incomparable, both "fully shared"
```

Grounded in three converging patterns: object-capability attenuation (delegate may only
restrict), Denning lattice-flow (labels flow one way), CRDT join-semilattice monotonicity
(state only inflates). "Once local, can't flip to sync" = a row's shareability may only
decrease; widening requires a **destructive uninstall + reinstall** under a new
`instance_name` + new `replication_id` (state deliberately not carried — mixing
private-era history into a now-shared DAG *is* the leak).

Two enforcement points; the second is the teeth:
1. **Registry-mutator guard** (`may_transition_to`) — defense-in-depth. The
   registry keeps a per-`instance_name` `ConsistencyFloorRow` recording the narrowest
   shareability tier a name was ever installed at; the floor **survives `uninstall`** (the
   `AgentRow` does not), so reusing a name to widen it (e.g. re-installing a formerly-`Local`
   channel as `Crdt`) returns `STATUS_CONSISTENCY_WIDEN_DENIED`. A live row still
   reports `STATUS_INSTANCE_EXISTS` first, so the guard only fires on the
   uninstall→reinstall-wider path. This stops honest replicas from ever *recording* a
   widening; it cannot stop a forged/CRDT-merged floor or row (that's why #2 is the teeth).
2. **Host-side sealed floor** (LOAD-BEARING) — the registry is replicated and **not
   trusted**, so a forged/merged `AgentRow` could flip `Local→Crdt`. The host persists,
   host-locally, the narrowest tier an `instance_name` was ever spawned at; at the
   sync-attach chokepoints (`vos/src/node.rs`, the `Crdt`/`Raft` branches in
   `register_inner`) the seal keys on the *sealed* value, so a `Local`-sealed keystore can
   never get a sync thread or raft worker even if the row lies.

Files: `vos/src/node.rs` (`Consistency` enum + lattice + seal),
`actors/space-registry` (`ConsistencyFloorRow` + `shareability`/`may_transition_to` +
`STATUS_CONSISTENCY_WIDEN_DENIED`), `vosx` `install.rs` (operator message for the denied
status).

**`TrustedDeviceSync (u8=4)`** is reserved for the device-sync plane below. The tier is only
meaningful with that plane's device-circle serving gate; until that exists it behaves
identically to `Local`. **Wire-compat:** a new node writes `AgentRow.consistency = 4`; an old
replica decodes it via `consistency_from_u8(4) → None → RowConfig::BadConsistency` (`up.rs`),
which `warn`s and **skips spawning** the agent — non-fatal, no data corruption, and correct
(an old node is not in that user's device circle, so it *should* not run the agent). Slotting
the tier in needs only `shareability()` to rank `TrustedDeviceSync` between `Local` and
`Crdt`/`Raft` (the seal stores the `Consistency` byte, not the shareability rank, so the
renumber is non-breaking) plus `from_u8(4) ⇒ Some(TrustedDeviceSync)`.

### Host-seed + forward-ratcheting CSPRNG behind the MLS RNG

`HostRand` (`extensions/messenger/src/host_rand.rs`) is an HKDF-SHA256 forward-ratchet: a
monotonic per-draw counter is bound into `info`, the `Zeroizing` state is wiped on advance,
and per boot it reseeds `state0 = Expand(Extract(salt=boot_token, ikm=seed),
info=DOMAIN‖"init"‖device_id‖boot_epoch)`. Per draw `out = HKDF-Expand(state,
info=domain‖purpose‖monotonic-counter[‖beacon])`, then `state' = HKDF-Expand(state,
"ratchet")`, the old state is zeroized and persisted crash-consistently before `out`
returns, and the ratchet never rewinds. `PublicBeacon` is a distinct newtype with no path
into the PRK — the beacon enters only the output-branch `info`.

The seed is node-local `csprng_seed` on the `Messenger` actor, set by a one-shot `seed()`
`#[msg]` (like the clerk IVK secret — **not** `AgentConfig.storage` install args, which only
ever carry the public init key) or lazily from OS entropy on `register`, threaded through one
chokepoint `Messenger::open_mls()`. The per-boot token is fresh entropy per open with a
**hard-fail on entropy error** (the live cross-boot reuse defense).

Randomness originates at **three** seams, not one: (1) `provider.rand()` — covered by the
CSPRNG swap; (2) the Ed25519 signer — seed-derived `SignatureKeyPair::from_raw` in
`mls::derive_signer` rather than `OsRng`; (3) **HPKE Seal's ephemeral KEM key** — closed by
the deterministic `CipherSuiteProvider` (below; in OpenMLS this seam is structurally
unreachable through the provider). The determinism gate: same seed ⇒ identical KeyPackage
bytes + signer + exported group secret.

**Rejected seam:** a `getrandom` custom backend — process-global (hits libp2p/TLS/everything)
and only intercepts the single seed draw, not per-message draws.

### The PVM-native messenger

The messenger runs the seed-CSPRNG over Local state and installs as a `consistency="local"`
PVM `[[agent]]`.

**In-PVM MLS crypto is a bounded port, not a precompile blocker.** The *whole* ciphersuite-1
stack — X25519 DH, Ed25519 sign/verify, AES-128-GCM, SHA-256, HKDF, all pure no_std
RustCrypto — compiles, transpiles through `grey_transpiler::link_elf`, and runs correctly
inside the PVM, using only the existing blake2b precompile (ID 100, for GroupId).
curve25519-dalek resolves to its serial u64/u128 backend (M-extension ops the transpiler
supports); the +e 16→13-register squeeze is a non-issue. No new precompile is needed for
correctness — precompiles are a *performance* follow-on (X25519 scalar-mult highest-value
first, then SHA-256/Ed25519), wired one-at-a-time as `cfg(riscv64)` ECALL dispatch with the
software path as fallback (the blake2b pattern). Ristretto is a clerk/ECVRF primitive — it
does **not** touch the messenger.

**Library: mls-rs (AWS), not OpenMLS.** OpenMLS 0.8.1 is irreducibly std — no `#![no_std]`,
a **non-optional `rayon`** dep (TreeKEM `par_iter`, gated only against wasm32 so the PVM
target *would* pull it), `SystemTime` in KeyPackage lifetime, `std::collections` across ~20
modules. mls-rs makes std+rayon optional features that drop under `--no-default-features`
(alloc-only core; ciphersuite 1 via `mls-rs-crypto-rustcrypto`, itself `no_std`). The
clincher: the **HPKE-Seal ephemeral** is *structurally unreachable* through OpenMLS's provider
(hpke-rs draws its own `from_entropy` ChaCha per call), but mls-rs fans entropy across
`CipherSuiteProvider::random_bytes` + a `DhType`/signer sub-seam, so a custom provider closes
it. **Wire compat:** msg-log/msg-ctl carry opaque RFC-9420 `MLSMessage` bytes (msg-log only
shape-checks the `PrivateMessage` prefix), and both libs emit RFC-9420 suite-1 framing — the
channel actors and their rkyv rows need **no change**.

The design:

- **Host boot-context seam.** The `BOOT_CONTEXT` hostcall (id 120, cap-installed via
  `install_vos_precompile_caps`, handled in `handle_refine_hostcall`) writes
  `boot_token(32) ‖ device_id(32) ‖ boot_epoch(u64 LE)`. The host mints a **fresh OS-entropy
  `boot_token` on every refine (re)entry — cold AND warm restart** (`BootContextHost` in
  `runtime.rs`), a host-local `device_id`, and a per-service **monotonic `boot_epoch`**.
  Guest stub `vos::hostcalls::boot_context`. The `boot_epoch` is monotonic within a process
  (the fresh token already defends cold-clone + warm-restart); durable cross-process
  `boot_epoch` persistence and real per-device `device_id` provenance (e.g. the node's libp2p
  identity) are open follow-ons.
- **mls-rs port of `mls.rs` behind the existing API.** Client-centric (a `Client<impl
  MlsConfig + use<>>` built per-dispatch via `mls::build_client`, no per-call provider),
  custom **`GroupStateStorage` + `KeyPackageStorage` over `BTreeMap`** (`store.rs`, shared via
  `Arc<Mutex>`, `max_past_epochs=64` enforced as trim-on-write since mls-rs has no config
  knob), the **signer derived deterministically from the seed** (HKDF→Ed25519, no OsRng), MLS
  rules = PURE ciphertext + in-band ratchet tree, commit processing auto-applies
  (`process_incoming_message`), eviction via `CommitEffect::Removed` (no `is_active`), explicit
  `Group::write_to_storage()` after every mutation. **Known deltas:** (1) sender-ratchet window
  is the fixed `MAX_RATCHET_BACK_HISTORY=1024`, not OpenMLS `(64,2000)` — harmless for the
  per-sender causal log; (2) KeyPackages are `MlsMessage`-wrapped (a fresh directory format, no
  deployed OpenMLS members to interop with).
- **Custom deterministic `CipherSuiteProvider`** (`extensions/messenger/src/crypto_provider.rs`).
  The injection seam was `DhType::generate()`: in mls-rs both `kem_generate` AND the HPKE
  ephemeral (`hpke_seal`/`hpke_setup_s`) route through `DhKem::encap → self.dh.generate()`, so
  a `DeterministicEcdh` (override `generate` to draw the X25519 keypair from `HostRand`,
  delegate the rest) determinizes **the ephemeral the stock provider drew from `OsRng`** (the
  seam OpenMLS structurally cannot reach). `VosCipherSuiteProvider` delegates all 24
  methods to an inner `RustCryptoCipherSuite` over that KEM, overriding only `random_bytes`;
  `VosCryptoProvider` yields it over an `Arc<Mutex<HostRand>>`. `signature_key_generate` stays
  `OsRng` but is off-path (the signer is the seed-derived identity). `ts_ms` is threaded into
  the KeyPackage + commit Lifetimes, so a fixed `(seed, boot token, ts_ms)` yields
  **bit-identical KeyPackages, commits, AND Welcomes**.
- **Two crate flavors off one source**, splitting on
  `cfg(target_arch = "riscv64")`: the host `.so` (std, mls-rs default features) and a **no_std
  riscv64 `#[actor]`** (mls-rs `default-features = false`). The cut: `now_ms()` reads
  `SystemTime` on the host and the `NOW_MS` hostcall in the actor; `build_client`'s boot token
  is OS entropy on the host and `BOOT_CONTEXT` in the actor; `store.rs`/`crypto_provider.rs`
  share state via `spin::Mutex` over an `Arc` that is `alloc::sync` on the host /
  `portable_atomic_util` on the no-atomics target; `core::error::Error`; a no-op
  `critical_section::Impl` + a fail-loud getrandom backend; mls-rs errors via `Debug`. The
  messenger **stays a host-workspace member** (so `cargo test -p messenger-extension --lib`
  keeps driving the .so). The messenger ELF transpiles clean through `link_elf`
  (`vos/tests/messenger_transpile.rs`, the make-or-break regression). `cargo +nightly actor`
  → a 2.7 MiB ELF.
- **Install + runtime support.** The messenger installs as an `[[agent]]` with
  `consistency = "local"`. The CLI/install/spawn/invoke machinery is **uniform across `.so`
  extensions and PVM-actor agents** (no extension-vs-agent branch), so the messenger's 13
  `#[msg(cli)]` verbs carry across the manifest unchanged. Supporting seams: the
  `NOW_MS` hostcall (id 121 — the messenger is the `ts_ms` ORIGIN and as a `Local` actor reads
  real host wall-clock); **device-local seed provisioning** (the seed never replicates, so it
  follows clerk-bridge's `bootstrap(secret)`: a node-local `device_secret = true` manifest
  flag; after spawn the daemon mints OS entropy into a `{data_dir}/agents/{svc_id}.seed`
  sidecar (0600) and sends a `seed` message, idempotent); `AgentConfig::tick_ms` (a tick loop
  mirroring the extension heartbeat); `AgentConfig::intra_caps` (opt-in caller-relay: an agent
  defaults to the trusted `Caller::Actor` bypass, and only one declaring `intra_caps` relays
  the real caller bounded per cap); and **raft leader-forward**
  (`agent_forward_to_raft_leader`, re-sending a follower's dropped write to the leader).
- **Per-channel discipline.** Mixing cdylib and PVM clients inside one live group is unsafe
  (non-normative encoding divergence risks a `tick.rs` `desynced` freeze); each channel rides
  the immutable-local reinstall discipline (new instance_name + replication_id + fresh group).
  Measure per-dispatch gas.

**Determinism gate:** *in-PVM* (mls-rs↔mls-rs, same seed → same bytes) is the gate — the
deterministic provider closes the HPKE-seal seam (via the `DhType::generate` wrap), so the
provider's entropy draws (KEM keypair, HPKE ephemeral, `random_bytes`) are bit-identical from
a fixed (seed, boot), and the `ts_ms` threading closes the KeyPackage/commit timestamp gap, so
full KeyPackage/commit/Welcome bytes are deterministic. *Cross-library* (OpenMLS↔mls-rs)
bit-exactness is impossible (different ephemerals + non-normative encoding) and is **not** the
gate — moot for an all-mls-rs deployment with no live OpenMLS counterpart.

**Open follow-ons:** durable cross-process `boot_epoch` persistence; real per-device
`device_id` provenance; crash-consistency of the persisted counter+epoch before ciphertext
posts (the BOOT_CONTEXT seam exists; durable persistence is the open piece — see must-solve
risk #5).

### Verifiable randomness actor (public beacon)

The public-beacon plane is the `chronos` clock+randomness actor. A PVM actor has **only
blake2b** today (`vos::crypto` exposes nothing else — no ed25519/ristretto/sign), so the
beacon cannot be "leader-signed"; it is a blake2b hash-chain of **contributed entropy**:
`beaconₙ = H(domain‖beaconₙ₋₁‖n‖entropyₙ)`, genesis `H(domain‖0‖0‖0)`. Each round stores
`(round, prev, entropy, beacon)` → tamper-evident + recomputable (`verify_round`); on Raft
it is one agreed sequence. Reads (`current`/`round_at`/`round`) are open to members;
`init`/`advance` are gated to `Advancer` (Raft leader / `System` driver); history is bounded
to 1024 rounds. **Trust boundary**: the round driver contributes the entropy and could grind
it — consumers trust it not to bias. This is the "verifiable-but-trusted" tier; the VRF that
adds public verifiability + bias-resistance is the ECVRF upgrade below.

**The messenger's beacon hedge:** `mls::build_client_hedged` folds `chronos.latest_final()` —
domain-bound via blake2b to its round — into the MLS CSPRNG's HKDF **output** branch only
(never seed/salt/ratchet, so confidentiality still rests on the secret seed; RFC 9180
§9.7.5). The 5 key-minting messenger handlers
(`key_package`/`create`/`send`/`stock_directory`/`commit_chain_op`) fetch it via
`clients::chronos_beacon`; **absent chronos ⇒ None ⇒ byte-identical to before** (so the
chronos-free path is unaffected).

**Bias resistance** (see [`chronos-bias-resistance.md`](./chronos-bias-resistance.md)):
**ECVRF over Ristretto255** (the standard `ECVRF-RISTRETTO255-SHA512` ciphersuite — SHA-512,
not blake2b), composed over the raft voters via a commit-reveal round protocol: input
`alpha = H(prev_beacon‖round)` (kills pre-input grinding) + committee fold of voters' VRF
outputs (one honest voter randomizes the round). ECVRF is the fit because verify's heavy ops
are the scalar-mults/point-adds VOS already accelerates; **threshold-BLS drand is ruled out**
(BLS verify is a pairing on BLS12-381 — no pairing precompile, wrong curve). The `vrf` crate
(`ECVRF-RISTRETTO255-SHA512`) + the round protocol provide it; the in-PVM ristretto/edwards
precompile wiring into `vos::crypto` is the gate for running verify *inside* a PVM actor (the
ECVRF path is host-side until then).

**Facts to build on:** an ECVRF proof is **80 bytes** (Gamma 32 + c 16 + s 32), not 96;
verify does *not* reduce to exactly the existing precompiles — there is no point/scalar-negate
ECALL (fold negation into the scalar via `c·(l−1)`), and verify also needs hash-to-curve
(Elligator; present host-side but not an ECALL — the dominant un-accelerated cost) plus the
wide hash (SHA-512 per the standard suite; a blake2b substitution would be sound but
non-standard and lose drand/Sui interop). Measure the hash-to-curve trace cost; add a
hash-to-ristretto ECALL if it bites.

The beacon is the public source for fairness AND an optional hedge into the HKDF `info`
(never a key source).

### Trusted device-sync plane (blocked on device enrollment)

A per-user **device circle** — a trust plane separate from the messaging crypto — that
replicates the user's *encrypted* private state (rkyv keystore snapshot + plaintext
history) among **only that user's own enrolled devices**, never onto the space. Each device
keeps its **own MLS leaf** in the shared groups (WhatsApp / RFC 9750 multi-client model —
clean PCS; the shared-keystore model is rejected because concurrent ratchet advance
corrupts forward-secrecy). New device admitted by a sponsor device's signed voucher and/or
a user recovery secret. History sync is a **separate one-shot encrypted archive** (the
universal pattern: Signal/WhatsApp/Matrix/Apple all do this — history is never a property
of the group ratchet). Prefer **per-device seeds** (no seed ever crosses devices — keeps
"seed never replicates" absolute).

Implement as the `TrustedDeviceSync` tier: reuse CRDT replication but gate serving more
strictly than `sync_serve_allowed` — serve only to peers whose libp2p PeerId resolves to a
device of the *same owner*. Prereq: device-enrollment infra (`project_identity_devices`
sketch + ssh-console device-enroll) that does not yet exist.

## Dependencies

| Work item | Depends on |
|---|---|
| Immutable-local consistency | — |
| Host-seed + ratcheting CSPRNG | immutable-local |
| PVM-native messenger | CSPRNG |
| Verifiable randomness actor | immutable-local (parallel to the messenger) |
| Trusted device-sync | immutable-local + device enrollment (not built) |

## Must-solve risks

1. **State/snapshot/fork reuse is the dominant hazard.** Any PVM warm-restart, redb
   restore, or row replay that resurrects an *old* CSPRNG state re-emits used MLS
   randomness ⇒ key/nonce reuse ⇒ compromise (Ristenpart–Yilek; the very reason MLS has the
   §6.3.1 reuse-guard). Empirically live given the PVM warm-restart bugs already on record.
   Fold a per-boot uniqueness token (VM-Generation-ID analogue) into the state before the
   first draw — **mandatory**.
2. **Sealed-floor is load-bearing** because the registry is not trusted (a guard living
   only in the registry actor is bypassable by a forged/merged row).
3. **Beacon-as-entropy collapse** — must be structurally impossible (beacon only as `info`).
4. **Forward-secrecy vs zk-replay tension** (novel; no clean MLS-in-zkVM prior art):
   per-draw ratchet+erase conflicts with re-deriving randomness for a proven trace. Decide
   explicitly whether secret draws are inside or outside any proven trace.
5. **Crash-consistency** of the counter in non-replicated Local state (advance+fsync before
   use, never rewind) — subtle, no replication safety net.
6. **In-PVM ECVRF is gated on the ristretto/edwards precompiles.** The messenger MLS crypto
   needs no new precompile (it runs the full ciphersuite-1 stack on the existing blake2b
   precompile), but the Ristretto/edwards precompiles wired into `vos/src/crypto` (today
   zkpvm-only) remain the gate for running the *ECVRF* path inside a PVM actor — a randomness
   concern, not a messenger one.

## Open questions for expert/crypto review

- MLS keygen determinism completeness (does any path bypass the deterministic provider?).
- Proving/replay vs forward-secrecy threat model (is the seed ever a prover witness?).
- Concrete per-boot uniqueness token available to a PVM actor on warm-restart/clone.
- Crash-consistency ordering primitive for a Local redb-backed PVM actor.
- Per-device seed vs circle-encrypted seed backup; no-server "lost all devices" recovery.
- Security review of a possible `ECVRF-RISTRETTO255-SHA512`→blake2b hash substitution for
  in-PVM acceleration (the standard SHA-512 suite keeps drand/Sui interop; a blake2b swap
  would lose it — is it worth it?); measured hash-to-curve cost (justify a hash-to-ristretto
  ECALL?).
- Forbid Crdt↔Raft lateral flips? (v0 allows rank-equal; sign-off needed.)
- `Ephemeral` is ranked *below* `Local` (shareability 0), so a name once installed
  `Ephemeral` cannot later widen to `Local` — internally consistent with the lattice and
  the host seal, but the doc draws `Ephemeral` as "orthogonal, non-persistent"; confirm
  whether the orthogonal reading should instead exempt it from the floor.
- Voter-pubkey attestation for committee aggregation (inherits the "registry replication
  trust" open review item).
