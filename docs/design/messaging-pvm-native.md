# PVM-native messaging: deterministic MLS, verifiable randomness, immutable locality, device-sync

Status: **design approved, P0 in progress** (branch `messaging`). This is the roadmap
for evolving the messenger off its native `.so` extension toward a portable PVM actor,
plus the supporting primitives. It was validated against the relevant RFCs and crate
sources (adversarial verification; corrections folded in below).

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
1. **Registry-mutator guard** (`may_transition_to`) — defense-in-depth.
2. **Host-side sealed floor** (LOAD-BEARING) — the registry is replicated and **not
   trusted**, so a forged/merged `AgentRow` could flip `Local→Crdt`. Persist, host-locally,
   the narrowest tier an `instance_name` was ever spawned at; at the sync-attach
   chokepoints (`vos/src/node.rs`, the `Crdt`/`Raft` branches in `register_inner`) key on
   the *sealed* value, so a `Local`-sealed keystore can never get a sync thread or raft
   worker even if the row lies.

Files: `vos/src/node.rs` (`Consistency` enum + lattice + seal), `actors/space-registry`
(guard + new `STATUS_CONSISTENCY_WIDEN_DENIED`; ELF rebuild), vosx `common.rs`
(`consistency_from_u8`/`_name`/`parse_consistency` + roundtrip test). Adding
`TrustedDeviceSync (u8=4)` changes a CRDT-replicated wire enum — decide the
old-replica-decodes-u8=4 compatibility story (today: `None` → safe-but-silent skip).

### P1 — Host-seed + forward-ratcheting CSPRNG behind the MLS RNG (cdylib spike)

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

### P2 — Make the messenger PVM-native (XL)

Port the messenger from cdylib to a PVM actor running P1's seed-CSPRNG over Local state;
the only entropy is the once-provisioned host seed. The real lift is running MLS's
HPKE/AEAD/hash in no_std PVM (leverage the blake2b precompile; Ristretto precompiles as
they get wired into `vos/src/crypto` — they exist today only in zkpvm). If switching
libraries, **mls-rs** (AWS) is the no_std-capable MLS (OpenMLS is not), supports cipher
suite 1 (VOS's suite) via `mls-rs-crypto-rustcrypto`; its RNG seam is
`CipherSuiteProvider::random_bytes` but the rustcrypto provider hard-codes `OsRng`, so a
custom provider is required — only worth it as a deliberate migration. Gate: bit-exact
reproduction of P1's KeyPackages/commits inside the PVM.

### P3 — Verifiable randomness actor (public beacon)

`v0`: raft-leader-signed blake2b hash-chain (verifiable-but-trusted). Then
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
- Voter-pubkey attestation for committee aggregation (inherits the "registry replication
  trust" open review item).
