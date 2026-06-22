# PVM-native messaging: deterministic MLS, verifiable randomness, immutable locality, device-sync

Status (branch `messaging`): **P0 done** (monotone-locality seal + registry widen-guard),
**P1 done** (host-seeded forward-ratcheting MLS CSPRNG, cdylib spike), **P3 done** (the
`beacon`→`chronos` clock+randomness actor, hardened with the Phase D bias-resistant
committee ECVRF — see [`chronos-bias-resistance.md`](./chronos-bias-resistance.md); a
pre-existing raft soft-restart bug was found + fixed there too, `654b2da`). **P2.0–P2.4
done** — the messenger runs on mls-rs with a deterministic host-seeded
`CipherSuiteProvider` (bit-identical KeyPackages/commits/Welcomes), and **the whole crate
now also builds as a no_std riscv64 `#[actor]` whose ELF transpiles clean through
`link_elf`** (the make-or-break). **P2.5 (live PVM e2e + RFC-interop + per-channel cutover)
is what remains.** Cross-space messaging follows P2. P4 (device-sync) stays blocked on
device-enrollment infra. This is the roadmap for evolving the messenger off its native
`.so` extension toward a portable PVM actor, plus the supporting primitives. Validated
against the relevant RFCs and crate sources (adversarial verification; corrections folded
in below), and the P2 crypto feasibility was confirmed by an empirical PVM spike (P2 is a
bounded port, NOT a precompile blocker). The full cross-track status + backlog lives in
[`messaging-roadmap.md`](./messaging-roadmap.md).

## Why

The messenger is a **native cdylib** today because OpenMLS needs `std` + OS entropy and
because MLS secrets must stay node-local. We want it **PVM-native** (portable RISC-V
bytecode — one artifact runs everywhere, no platform-specific binary). The blockers are
not really `std`; they are (1) the deterministic PVM has no entropy and (2) secrets must
never replicate. The four work items below dismantle both, plus add two capabilities the
operator wants (a verifiable space randomness beacon; trusted multi-device sync).

## Corrected randomness model (the load-bearing idea)

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

### P0 — Immutable-local consistency (no crypto risk; do first)

Model `Consistency` as a monotone **shareability lattice** and seal each agent so its tier
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
1. **Registry-mutator guard** (`may_transition_to`) — defense-in-depth. **LANDED.** The
   registry keeps a per-`instance_name` `ConsistencyFloorRow` recording the narrowest
   shareability tier a name was ever installed at; the floor **survives `uninstall`** (the
   `AgentRow` does not), so reusing a name to widen it (e.g. re-installing a formerly-`Local`
   channel as `Crdt`) returns the new `STATUS_CONSISTENCY_WIDEN_DENIED`. A live row still
   reports `STATUS_INSTANCE_EXISTS` first, so the guard only fires on the
   uninstall→reinstall-wider path. This stops honest replicas from ever *recording* a
   widening; it cannot stop a forged/CRDT-merged floor or row (that's why #2 is the teeth).
2. **Host-side sealed floor** (LOAD-BEARING; **LANDED** in `765989a`) — the registry is
   replicated and **not trusted**, so a forged/merged `AgentRow` could flip `Local→Crdt`.
   Persist, host-locally, the narrowest tier an `instance_name` was ever spawned at; at the
   sync-attach chokepoints (`vos/src/node.rs`, the `Crdt`/`Raft` branches in
   `register_inner`) key on the *sealed* value, so a `Local`-sealed keystore can never get a
   sync thread or raft worker even if the row lies.

Files: `vos/src/node.rs` (`Consistency` enum + lattice + seal — landed),
`actors/space-registry` (`ConsistencyFloorRow` + `shareability`/`may_transition_to` +
`STATUS_CONSISTENCY_WIDEN_DENIED` + ELF rebuild — landed), `vosx` `install.rs` (operator
message for the denied status — landed).

**`TrustedDeviceSync (u8=4)` — DEFERRED (decision 2026-06-13).** The tier is only meaningful
with P4's device-circle serving gate, which is blocked on device-enrollment infra that does
not exist; adding the variant now would churn every `Consistency` match (node.rs, up.rs,
reconcile.rs, common.rs) for a tier that would behave identically to `Local`, and force a
premature wire commitment. **Wire-compat story (verified, safe for when P4 lands):** a new
node writes `AgentRow.consistency = 4`; an old replica decodes it via
`consistency_from_u8(4) → None → RowConfig::BadConsistency` at `up.rs:614`, which `warn`s and
**skips spawning** the agent (`up.rs:535`) — non-fatal, no data corruption. That is exactly
the correct behaviour: an old node is not in that user's device circle, so it *should* not
run the agent. When P4 lands, only `shareability()` needs `TrustedDeviceSync` slotted between
`Local` and `Crdt`/`Raft` (the seal stores the `Consistency` byte, not the shareability rank,
so this renumber is non-breaking) plus `from_u8(4) ⇒ Some(TrustedDeviceSync)`.

### P1 — Host-seed + forward-ratcheting CSPRNG behind the MLS RNG (cdylib spike)

**LANDED (cdylib spike).** New `extensions/messenger/src/host_rand.rs`: `HostRand`
(HKDF-SHA256 forward-ratchet, monotonic per-draw counter bound into `info`, `Zeroizing`
state wiped on advance, per-boot reseed `state0 = Expand(Extract(salt=boot_token,
ikm=seed), info=DOMAIN‖"init"‖device_id‖boot_epoch)`) + `VosProvider` (returns `HostRand`
from `rand()`, delegates `crypto()`→RustCrypto / `storage()`→MemoryStorage) +
`PublicBeacon` (a distinct newtype with no path into the PRK — beacon enters only the
output-branch `info`). Seed is node-local `csprng_seed` on the `Messenger` actor, set by a
one-shot `seed()` `#[msg]` or lazily from OS entropy on `register`; threaded through one
chokepoint `Messenger::open_mls()`. Per-boot token = fresh `getrandom` per open, **hard-fail
on entropy error** (it is the only live cross-boot reuse defense in the spike;
`device_id`/`boot_epoch`/`persisted_ctr` are plumbed but host-fed in P2/P4).

The audit (two adversarial-verification workflows) found randomness originates at **three**
seams, not one: (1) `provider.rand()` — covered by the swap; (2) the Ed25519 signer —
`SignatureKeyPair::new()` used `OsRng`, now replaced by seed-derived
`SignatureKeyPair::from_raw` in `mls::derive_signer`; (3) **HPKE Seal's ephemeral KEM key** —
drawn from hpke-rs's own per-call `from_entropy()` ChaCha, *unreachable through the
provider*. So commit/Welcome **wire bytes stay non-deterministic** (carved out to P2: a
custom `OpenMlsCrypto` seeding the hpke prng, or a backend swap); the group **secret** state
still converges. P1 gate met: same seed ⇒ identical KeyPackage bytes + signer + exported
group secret (`mls::tests::same_seed_yields_identical_key_package`, the ported group-flow /
commit-race / eviction tests, both e2e). Original plan text below.

Custom `HostRand` impl of `openmls_traits::random::OpenMlsRand` (`random_array`,
`random_vec`) + a thin custom `OpenMlsProvider` returning it from `rand()` while delegating
`crypto()`/`storage()` to stock RustCrypto + the existing snapshot store. Swap
`OpenMlsRustCrypto` for it in `extensions/messenger/src/mls.rs`; `random_32` /
`fresh_replication_id` / `welcome_nonce` / the KeyPackage builder keep working via
`provider.rand()`.

- Seed delivered via a runtime `seed(seed_bytes)` `#[msg]` (like the clerk IVK secret),
  **not** `AgentConfig.storage` install args (those only ever carry the public init key).
- Construction (hedged HKDF ratchet): keep a 32-byte state seeded once; per draw
  `out = HKDF-Expand(state, info=domain‖purpose‖monotonic-counter[‖beacon])`,
  `state' = HKDF-Expand(state, "ratchet")`, **zeroize old state**, **persist
  crash-consistently before returning `out`**, never rewind.
- Audit determinism completeness (two providers, same seed ⇒ identical KeyPackages/commits)
  — some OpenMLS keygen may route through `crypto()` rather than `rand()`.
- Do it as a native-cdylib spike first (full host access) to de-risk before PVM.

**Rejected seam:** `getrandom` custom backend — process-global (hits libp2p/TLS/everything)
and only intercepts the single seed draw, not per-message draws.

### P2 — Make the messenger PVM-native (XL — scoped, not started)

Port the messenger from cdylib to a PVM actor running P1's seed-CSPRNG over Local state.
**Groundwork done (this scoping pass + an empirical spike); decisions below are evidence-backed.**

**Bottom line: P2 is a bounded port, NOT a precompile blocker.** The fear in "must-solve risk
#6" (in-PVM crypto) is empirically dead: a spike actor (`actors/_crypto_spike`) exercising the
*whole* ciphersuite-1 stack — X25519 DH, Ed25519 sign/verify, AES-128-GCM, SHA-256, HKDF, all
pure no_std RustCrypto — **compiles, transpiles through `grey_transpiler::link_elf`, and runs
correctly inside the PVM** (self-consistency checks pass; ~0.23 s for load+a full crypto
exercise), using only the existing blake2b precompile (ID 100, for GroupId). curve25519-dalek
resolves to its serial u64/u128 backend (M-extension ops the transpiler supports); the +e
16→13-register squeeze is a non-issue. **No new precompile is needed for correctness** — they
become a P3 *perf* follow-on (X25519 scalar-mult the highest-value first, then SHA-256/Ed25519),
wired one-at-a-time as `cfg(riscv64)` ECALL dispatch with the software path as fallback (the
blake2b pattern). Ristretto is a clerk/ECVRF primitive — it does **not** touch the messenger.

**Library decision: migrate OpenMLS → mls-rs (AWS).** OpenMLS 0.8.1 is irreducibly std — no
`#![no_std]`, a **non-optional `rayon`** dep (TreeKEM `par_iter`, gated only against wasm32 so
the PVM target *would* pull it), `SystemTime` in KeyPackage lifetime, `std::collections` across
~20 modules. mls-rs makes std+rayon optional features that drop under `--no-default-features`
(alloc-only core; ciphersuite 1 via `mls-rs-crypto-rustcrypto`, itself `no_std`). The clincher:
the **HPKE-Seal ephemeral** — the one non-determinism P1 carved out — is *structurally
unreachable* through OpenMLS's provider (hpke-rs draws its own `from_entropy` ChaCha per call),
but mls-rs fans entropy across `CipherSuiteProvider::random_bytes` + a `DhType`/signer sub-seam,
so a custom provider closes it. **Wire compat:** msg-log/msg-ctl carry opaque RFC-9420
`MLSMessage` bytes (msg-log only shape-checks the `PrivateMessage` prefix), and both libs emit
RFC-9420 suite-1 framing — the channel actors and their rkyv rows need **no change**.

**Phases** (each gated; ~4–6 focused sessions total — the two XL poles are the mls-rs API
migration and the make-or-break transpile of mls-rs's *own* code):

- **P2.0 — in-JAVM crypto execution gate (M). DONE (crypto-exec gate).** `_crypto_spike` grew
  parametric `tv_{sha256,hkdf,x25519,ed25519,aes}` `#[msg]` handlers (each takes an input, returns
  the raw primitive output) plus a self-scheduling `warm_rounds` handler that re-runs the whole
  stack across `new_warm` re-entries and folds each round's digest. `vos/tests/crypto_spike_pvm.rs`
  loads the ELF, drives every handler over several inputs, and asserts the PVM-computed bytes are
  **bit-exact against host RustCrypto** for all five primitives — and that the crypto path is clean
  across a warm restart (every round reproduces round 0, monotone fold matches a host reproduction,
  zero guest panics). 6/6 green; closes the execution gap the compile spike left. **Wire-name note:**
  the `#[msg]` macro mints a PascalCase struct per handler, so handlers carry a `tv_` prefix (an
  un-prefixed `sha256` would mint `Sha256` and collide with `sha2::Sha256`). **Fold-in RESOLVED ✅
  — mls-rs's own code transpiles.** `actors/_mls_spike` (mls-rs 0.55 `--no-default-features` +
  `mls-rs-crypto-rustcrypto`, a real two-client create-group + add-member-commit + `MlsMessage`
  codec round-trip) builds to a 1.46 MiB riscv64em-javm ELF and transpiles to a 1.31 MiB PVM blob
  through the same `grey_transpiler::link_elf` the repo uses (`vos/tests/mls_spike_transpile.rs`
  guards it). `rayon` is confirmed absent from the riscv dep tree; the sync API (no
  `mls_build_async`) composes with the single-poll model (de-risks P2.2). Two no_std build-outs
  surfaced, both spike-only and already anticipated downstream: a `getrandom` custom backend (real
  port routes entropy through the P2.3 deterministic `CipherSuiteProvider`) and a
  `critical-section`/`portable-atomic` shim for the in-memory storage `spin::Mutex` (real port
  swaps the in-memory store for the P2.2 alloc-`BTreeMap` `GroupStateStorage`, dropping the Mutex).
  **The library decision (OpenMLS → mls-rs) is empirically confirmed; P2's dominant residual
  unknown is closed.**
- **P2.1 — host boot-context seam (L). DONE (the seam; messenger wiring is P2.4).** New
  `BOOT_CONTEXT` hostcall (id 120, cap-installed via `install_vos_precompile_caps`, handled in
  `handle_refine_hostcall`): writes `boot_token(32) ‖ device_id(32) ‖ boot_epoch(u64 LE)` into a
  guest buffer. The host mints a **fresh OS-entropy `boot_token` on every refine (re)entry — cold
  AND warm restart** (`BootContextHost` in `runtime.rs`, a process-global behind `getrandom`), a
  host-local `device_id`, and a per-service **monotonic `boot_epoch`**. Guest stub
  `vos::hostcalls::boot_context`. Verified by `pvm_boot_context_fresh_across_warm_restart`: across
  `new_warm` re-entries the tokens are all distinct, `boot_epoch` increments by one, and `device_id`
  is stable. **Deferred to when the messenger is a PVM actor (P2.4):** re-booting `HostRand` from
  `(seed, token, device_id, boot_epoch, persisted_ctr)` at the top of every refine entry; durable
  **cross-process** `boot_epoch` persistence (today in-memory → monotonic within a process only, the
  fresh token already defends cold-clone + warm-restart); real per-device `device_id` provenance
  (e.g. the node's libp2p identity). The seam was independent of the lib, so it landed first.
- **P2.2 — mls-rs port of `mls.rs` behind the existing API, host build (XL). DONE.** The whole
  messenger crate (`mls.rs`, `host_rand.rs`, `lib.rs`, `tick.rs` + new `store.rs`) now runs on
  mls-rs 0.55 and compiles + passes its tests. Structural shift absorbed: **Client-centric** (a
  `Client<impl MlsConfig + use<>>` built per-dispatch via `mls::build_client`, no per-call provider;
  `use<>` so it doesn't borrow `self`), custom **`GroupStateStorage` + `KeyPackageStorage` over
  `BTreeMap`** (`store.rs`, shared across Client clones via `Arc<Mutex>`, snapshot/restore both maps,
  `max_past_epochs=64` enforced as the store's trim-on-write since mls-rs has no config knob), the
  **signer derived deterministically from the seed** (HKDF→Ed25519 64-byte keypair, no OsRng), MLS
  rules = PURE ciphertext (`encrypt_control_messages=true`) + in-band ratchet tree, **commit
  processing auto-applies** (no staged-commit/merge — `process_incoming_message`), eviction detected
  via `CommitEffect::Removed` (mls-rs has no `is_active`), and **explicit `Group::write_to_storage()`
  after every mutation** (mls-rs doesn't auto-persist). **Gate MET:** group-flow / commit-race /
  eviction tests pass against mls-rs on the host (`cargo test -p messenger-extension --lib` → 11/11;
  the commit-race converges to a byte-identical `export_secret`). **Async-API question RESOLVED:**
  mls-rs's default (no `mls_build_async`) build is fully synchronous — the storage traits are plain
  sync `fn`s and compose directly with the single-poll handler model. **Known deltas (documented):**
  (1) the sender-ratchet window is the fixed `MAX_RATCHET_BACK_HISTORY=1024`, not the OpenMLS
  `(64,2000)` — more back-tolerance, stricter forward cap, harmless for the per-sender causal log;
  (2) KeyPackages are now `MlsMessage`-wrapped (not byte-compatible with the old OpenMLS bare-KP
  directory format — a fresh format, no deployed OpenMLS members to interop with); (3) determinism
  is signer-only for now (KEM/HPKE entropy still OsRng) — full bit-exactness is **P2.3**. The two
  heavy e2e/RFC-interop tests are deferred to P2.5; `tests/e2e.rs` compiles unchanged (it drives the
  actor via the CLI/`Msg` interface). The Cargo dep swapped OpenMLS → `mls-rs`/`mls-rs-core`/
  `mls-rs-codec`/`mls-rs-crypto-rustcrypto` (host default features; the no_std cut is **P2.4**).
- **P2.3 — custom deterministic `CipherSuiteProvider` (L). DONE (host build).** New
  `extensions/messenger/src/crypto_provider.rs`. The injection seam turned out to be
  `DhType::generate()`: in mls-rs both `kem_generate` AND the HPKE ephemeral
  (`hpke_seal`/`hpke_setup_s`) route through `DhKem::encap → self.dh.generate()`, so a
  `DeterministicEcdh` wrapping RustCrypto's `Ecdh` (override `generate` to draw the X25519 keypair
  from `HostRand`, delegate the rest) determinizes **the ephemeral the stock provider drew from
  `OsRng` — the seam OpenMLS structurally could not reach**. `VosCipherSuiteProvider` delegates all
  24 `CipherSuiteProvider` methods to an inner `RustCryptoCipherSuite` over that KEM, overriding only
  `random_bytes`; `VosCryptoProvider` yields it over an `Arc<Mutex<HostRand>>` so the Client's
  provider clones advance one ratchet in order. `build_client` boots `HostRand` from the seed + a
  fresh per-open OS token. **`signature_key_generate` stays `OsRng` but is off-path** (the signer is
  the seed-derived identity handed to the Client; mls-rs never generates a signature key in
  create/commit/keypackage/welcome). **Gate MET:** `host_seeded_provider_is_deterministic` asserts
  bit-identical KEM keypair + HPKE `kem_output`/`ciphertext` + `random_bytes` from the same (seed,
  boot token), forked by a different token. **Byte-determinism CLOSED** (a P2.4 down-payment landed
  with P2.3): `ts_ms` is now threaded into the KeyPackage + commit Lifetimes (`new_key_package(_,
  ts_ms)` → `Some(MlsTime)`; `create_group_with_id`/`CommitBuilder::commit_time`), so a fixed
  `(seed, boot token, ts_ms)` yields **bit-identical KeyPackages, commits, AND Welcomes** —
  `same_seed_boot_and_ts_yields_identical_{key_package,commit_and_welcome}` (14/14 lib tests). The
  remaining `OsRng` reachable in-PVM (it traps) is closed by P2.4's no_std cut + the deterministic
  provider being the only one wired; `now_ms()` is now the single time seam that becomes host-fed
  when the messenger runs as a PVM actor.
- **P2.4 — cut the messenger crate to the PVM actor flavor (XL). DONE.** The whole
  messenger crate now builds in two flavors off one source, splitting on
  `cfg(target_arch = "riscv64")` (the same discriminator the `#[actor]`/`#[messages]` macros
  use): the host `.so` (vos `extension`, std, mls-rs default features — behaviourally
  unchanged) and a **no_std riscv64 `#[actor]`** (vos `macros,service`, mls-rs +
  `default-features = false`). The cut: `now_ms()` reads `SystemTime` on the host and a
  wire-threaded seam (`set_wire_now_ms`, default 0 until P2.5) in the actor (a PVM guest has
  no clock and there is no time hostcall — the deterministic provider already pins the
  bytes); `build_client`'s boot token is OS entropy on the host and the **BOOT_CONTEXT
  hostcall** (the P2.1 seam, fresh per refine entry) in the actor; `mls::random_32`
  (non-key-material) draws OS entropy / boot-token+counter; `register` makes the seed
  mandatory in the actor; `store.rs`/`crypto_provider.rs` share state via `spin::Mutex` over
  an `Arc` that is `alloc::sync` on the host / `portable_atomic_util` on the no-atomics
  target (mirroring mls-rs's own in-memory providers); `core::error::Error`; per-module
  `alloc` imports; a no-op `critical_section::Impl` + a fail-loud getrandom backend
  (cfg riscv64); mls-rs errors formatted via `Debug` (no `Display` without std). The build
  scaffolding (per-target `Cargo.toml` deps, crate-local `.cargo/config.toml`,
  `riscv64em-javm.json`) models `actors/chronos` / `_crypto_spike`; the messenger **stays a
  host-workspace member** (so `cargo test -p messenger-extension --lib` keeps driving the
  .so), so its ELF lands in the shared workspace target dir. **Gate MET: the messenger ELF
  transpiles clean through `link_elf`** (`vos/tests/messenger_transpile.rs`, the permanent
  regression) — the real make-or-break, beyond `_mls_spike`'s minimal flow now exercising the
  whole crate. Host gate green throughout (`cargo test -p messenger-extension --lib` →
  14/14). `cd extensions/messenger && cargo +nightly actor` → a 2.7 MiB ELF.
- **P2.5 — e2e PVM messenger + RFC-interop + clean cutover (L). Execution down-payment
  landed.** Beyond the `link_elf` transpile gate, `vos/tests/messenger_pvm.rs` proves the
  messenger actually **runs** as a PVM actor: it drives `seed` → `register` → `key_package`
  through `VosRuntime` and mints a clean KeyPackage, exercising the whole no_std MLS path at
  runtime (seed-derived Ed25519 signer, the deterministic X25519 KEM via the custom
  `DhType::generate`/`HostRand`, mls-rs framing, the `spin`+`portable-atomic` storage, rkyv
  state persistence across dispatches, the `BOOT_CONTEXT` hostcall). **Fork resolved:** the
  operator chose to **replace the `.so`** — the PVM messenger becomes the messenger (an
  `[[agent]]` with `consistency = "local"`). A 5-agent recon found that the CLI, install,
  spawn, and invoke machinery is **uniform across `.so` extensions and PVM-actor agents** (no
  extension-vs-agent branch — proven by `vosx … math add a=2 b=3` and
  `gateway_pvm_e2e.rs`), so the messenger's 13 `#[msg(cli)]` verbs survive the move untouched;
  the move is a manifest change (`[[extension]]` → `[[agent]]`, point `path` at the ELF) plus
  the two seams below. **Increment 1 done** — the `NOW_MS` hostcall (id 121, mirroring
  `BOOT_CONTEXT`): the messenger is the `ts_ms` ORIGIN (it stamps MLS Lifetimes + the
  msg-log/msg-ctl wire rows), and as a `Local` (non-replicated) actor it now reads real host
  wall-clock through the hostcall, so a freshly-minted KeyPackage carries a valid Lifetime a
  remote peer accepts (replaced the placeholder `set_wire_now_ms` static).
  **Increment 2 done — device-local seed provisioning:** the seed is the only confidentiality
  root and must never replicate, but `install_args`/`on_start` live in the *replicated*
  `AgentRow` — so it follows clerk-bridge's `bootstrap(secret)`: a new node-local
  `device_secret = true` manifest flag, and after spawn the daemon mints OS entropy into a
  node-local `{data_dir}/agents/{svc_id}.seed` sidecar (0600, like the P0 `.seal`) and sends a
  `seed` message via `node.invoke_with_timeout` (`Caller::System`), idempotent. **Validated
  live single-node:** a `consistency = "local"` messenger agent installs, gets "device seed
  provisioned", and `vosx messenger register / key_package / status` run end-to-end through the
  PVM agent (outbound resolve ask, a real-Lifetime KeyPackage, state persisted across
  dispatches). **Increment 3 — PVM-agent runtime support: DONE + validated live.** Three (it
  turned out four) opt-in/narrow runtime pieces, all landed: **(3a) agent ticking** —
  `AgentConfig::tick_ms` + a tick loop in `agent_thread` mirroring the extension heartbeat;
  **(3b) opt-in agent caller-relay** — `AgentConfig::intra_caps`; an agent's outbound invoke
  defaults to the trusted `Caller::Actor` (the bypass every existing agent→agent call relies
  on), and only an agent that declares `intra_caps` relays the real caller bounded per cap
  (the existing `RelayCallerGuard`/`resolve_relay_caller` machinery) — so a privileged
  downstream call needs a privileged original caller, preserving the `.so`'s ACL model without
  regressing existing agents; **(4th) raft leader-forward** — an agent's write to a local raft
  follower (a dropped reply) is re-sent to the leader (`agent_forward_to_raft_leader`, the sync
  analogue of `route_invoke`'s forward). The manifest gained node-local `tick_ms`/`intra_caps`
  on `[[agent]]`. **Validated live:** the 2-node e2e drives the PVM-agent messenger through
  register → create → send → join → grant → cross-node bob-register (bounded relay carries the
  admin caller through `create`→`registry.install`; raft-forward lets the follower-node
  messenger publish + commit). **LANDED — e2e GREEN under the recompiler.** The "guest-stack
  overflow" was a misdiagnosis: the channel-active `tick` failures were four codegen bugs, not a
  stack limit. Three were in grey-transpiler (a `CALL_PLT` `pending_load_imm` leak that desynced
  branch targets into mid-instruction traps; a `load_imm`+ALU mis-fusion on self-aliased operands
  and non-commutative shifts; a `load_imm`+load fusion that fired for `rd != rs1` and skipped the
  `address_map` update) and one in the javm JIT recompiler (a variable shift whose destination is
  `φ[12]`=RCX clobbered the shift count — mls-rs TreeKEM `imm << level` index math then produced
  wrong node indices → `InvalidLeafConsumption` on a joiner's encrypt and `InvalidNodeIndex` on
  member removal; the interpreter was correct, the JIT was not). All four are fixed in jar
  (`fix/pvm-transpiler-codegen`, merged to master); the heap-boxed drains stay. With them the
  2-node e2e (`two_nodes_exchange_e2ee_messages`) runs the full flow — register → create → invite →
  commit → Welcome → join → bidirectional E2EE → member removal — GREEN with the messenger as a
  `consistency="local"` PVM agent under the default JIT, and the manifest cutover has landed.
  **RFC-interop is moot** (the messenger is fully off OpenMLS; no live counterpart).
  **Clean cutover per channel** (new instance_name + replication_id + fresh group, riding
  P0's reinstall discipline) — do NOT bet on mixed cdylib+PVM inside one live group
  (non-normative encoding divergence risks `tick.rs` `desynced` freeze). Measure per-dispatch
  gas.

**Determinism gate (split by the lib swap):** *in-PVM* (mls-rs↔mls-rs, same seed → same bytes) is
ACHIEVABLE and IS the gate — and **P2.3 closed the HPKE-seal seam** (via the `DhType::generate`
wrap) that P1 couldn't, so the provider's entropy draws (KEM keypair, HPKE ephemeral, `random_bytes`)
are now bit-identical from a fixed (seed, boot) — and the KeyPackage/commit timestamp gap is
**closed** (P2.3's `ts_ms` threading), so full KeyPackage/commit/Welcome bytes are deterministic.
*Cross-library* (OpenMLS↔mls-rs) bit-exactness is IMPOSSIBLE (different ephemerals + non-normative
encoding) and is **not** the gate — relaxed to RFC-interop, proven by a cross-library test.

**Key risks:** (1) ~~P2.4 transpile of mls-rs's own code is the dominant residual unknown~~ —
**RETIRED by P2.0b**: the `_mls_spike` create-group+commit ELF transpiles through `link_elf`
(`mls_spike_transpile.rs`); the P2.4 gate remains `link_elf` not `cargo build`, but the make-or-break
is now known-good. (2) warm-restart nonce reuse is empirically live — re-boot HostRand per refine
entry with a host-minted fresh token (load-bearing, not optional) — **the BOOT_CONTEXT seam for this
landed in P2.1**. (3) ~~mls-rs's async provider API vs the single-poll model~~ — **RESOLVED in P2.2**:
the default (no `mls_build_async`) build is fully synchronous; the custom `GroupStateStorage`/
`KeyPackageStorage` are plain sync `fn`s and compose directly with the single-poll handler model. (4) cross-library desync —
clean cutover mitigates. (5) crash-consistency of the persisted counter+epoch before ciphertext
posts — **partially addressed**: the BOOT_CONTEXT seam exists; durable cross-process `boot_epoch`
persistence is the P2.4 follow-on. **Open questions** carried in the memory memo (~~mls-rs sync
facade; mls-rs transpile~~ both resolved by P2.0b; device_id provenance; BOOT_CONTEXT ABI;
warm-restart host hook; in-PVM `ts_ms` source).

### P3 — Verifiable randomness actor (public beacon)

**v0 LANDED** as the `beacon` actor (`actors/beacon`, `74ce61a`). Correction to the
original plan: a PVM actor has **only blake2b** today (`vos::crypto` exposes nothing else —
no ed25519/ristretto/sign), so v0 **cannot be "leader-signed"**; it is a blake2b hash-chain
of **contributed entropy** instead: `beaconₙ = H(domain‖beaconₙ₋₁‖n‖entropyₙ)`, genesis
`H(domain‖0‖0‖0)`. Each round stores `(round, prev, entropy, beacon)` → tamper-evident +
recomputable (`verify_round`); on Raft it's one agreed sequence. Reads
(`current`/`round_at`/`round`) open to members; `init`/`advance` gated to `Advancer` (Raft
leader / `System` driver); history bounded to 1024 rounds. **Trust boundary**: the round
driver contributes the entropy and could grind it — consumers trust it not to bias. This is
the documented "verifiable-but-trusted" tier; the signature/VRF that adds public
verifiability + bias-resistance is exactly what the ECVRF upgrade below provides, and is
**gated on ristretto/edwards precompiles being wired into `vos::crypto`** (a P3 crypto
concern — note P2 turned out NOT to need any precompile; see P2). Follow-ups: a host
round-driver (periodic `advance` with OS entropy on the leader) and
wiring the messenger's `PublicBeacon`/`set_beacon` hedge to read this beacon (info-only).

Then (the bias-resistant upgrade)
**ECVRF over Ristretto255** (`ECVRF-RISTRETTO255-BLAKE2B`, a custom frozen ciphersuite),
composed over the raft voters: input `alpha = blake2b(prev_beacon‖round)` (kills pre-input
grinding) + committee XOR of voters' VRF outputs (one honest voter randomizes the round).
ECVRF is the fit because verify's heavy ops are the scalar-mults/point-adds VOS already
accelerates; **threshold-BLS drand is ruled out** (BLS verify is a pairing on BLS12-381 —
no pairing precompile, wrong curve).

**Corrected facts** (don't build on the old assumptions): an ECVRF proof is **80 bytes**
(Gamma 32 + c 16 + s 32), **not 96**; verify does *not* reduce to exactly the existing
precompiles — there's no point/scalar-negate ECALL (fold negation into the scalar via
`c·(l−1)`), and verify also needs hash-to-curve (Elligator; present host-side but not an
ECALL — the dominant un-accelerated cost) plus a wide hash (standard suite wants SHA-512;
blake2b substitution = sound but non-standard, loses drand/Sui interop). Measure the
hash-to-curve trace cost; add a hash-to-ristretto ECALL if it bites.

Used as the public source for fairness AND as an optional hedge into P1's HKDF `info`
(never a key source).

### P4 — Trusted device-sync plane (XL; blocked on device enrollment)

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

## Sequencing

| Phase | Effort | Depends on |
|---|---|---|
| P0 immutable-local | M | — |
| P1 host-seed + ratcheting CSPRNG (cdylib spike) | L | P0 |
| P2 PVM-native port | XL | P1 |
| P3 randomness actor | L | P0 (parallel to P2) |
| P4 trusted device-sync | XL | P0 + device enrollment (not built) |

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
6. **P2 is XL and gated on in-PVM MLS crypto** + Ristretto precompiles wired into
   `vos/src/crypto` (today zkpvm-only). Do not under-scope.

## Open questions for expert/crypto review

- OpenMLS keygen determinism completeness (does any path bypass `RandProvider`?).
- Proving/replay vs forward-secrecy threat model (is the seed ever a prover witness?).
- Concrete per-boot uniqueness token available to a PVM actor on warm-restart/clone.
- Crash-consistency ordering primitive for a Local redb-backed PVM actor.
- Per-device seed vs circle-encrypted seed backup; no-server "lost all devices" recovery.
- Security review of the `ECVRF-RISTRETTO255-BLAKE2B` SHA-512→blake2b substitution;
  measured hash-to-curve cost (justify a hash-to-ristretto ECALL?).
- Forbid Crdt↔Raft lateral flips? (v0 allows rank-equal; sign-off needed.)
- `Ephemeral` is ranked *below* `Local` (shareability 0), so a name once installed
  `Ephemeral` cannot later widen to `Local` — internally consistent with the lattice and
  the host seal, but the doc draws `Ephemeral` as "orthogonal, non-persistent"; confirm
  whether the orthogonal reading should instead exempt it from the floor.
- Voter-pubkey attestation for committee aggregation (inherits the "registry replication
  trust" open review item).
