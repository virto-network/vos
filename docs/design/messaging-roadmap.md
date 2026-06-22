# Messaging roadmap & status (branch `messaging`)

Single bird's-eye index for the private-messaging work, so the detailed plans —
spread across two design docs + memory — don't get lost. Last updated 2026-06-16.

**The promise:** an end-to-end *private* communications protocol with *cross-space*
private messaging. Decomposed:

| Part | State |
|---|---|
| Real E2EE content privacy (OpenMLS, ciphertext-only replication, PCS) | ✅ done |
| The single-space messaging substrate (3 actors + edge crypto) | ✅ done (feature Phases 1–4) |
| Verifiable randomness the MLS CSPRNG hedges (the `chronos` clock+beacon) | ✅ done + bias-resistant (Phase D) |
| **Cross-space reach** | ❌ not built (feature Phase 5) |
| **Metadata privacy** (the depth of "private") | ⚠️ largely deferred |

## Two tracks

There are two interleaved roadmaps. Keep both findable.

**A — the messaging feature** (`[[project-messaging-design]]`, plan
`~/.claude/plans/staged-stirring-reef.md`):
Phase 1 two-node E2EE ✅ · 2 lifecycle/PCS + directory ✅ · 3 dynamic per-channel
agents ✅ · 4 sync hardening ✅ · **5 cross-space (next feature, not started)** ·
6 padding/epoch-suppression/GC/doc rewrite.

**B — PVM-native architecture** ([`messaging-pvm-native.md`](./messaging-pvm-native.md)):
P0 immutable-local ✅ · P1 host-seed ratcheting CSPRNG ✅ · **P2 PVM-native
messenger port — P2.0–P2.4 ✅ (messenger on mls-rs with a deterministic host-seeded
provider; the whole crate builds as a no_std riscv64 `#[actor]` whose ELF transpiles
through `link_elf` — the make-or-break); P2.5 (live PVM e2e + RFC-interop + cutover)
remains** · P3 verifiable-randomness actor ✅ (= `chronos`, hardened by
[`chronos-bias-resistance.md`](./chronos-bias-resistance.md)) · P4 trusted device-sync
(blocked on device enrollment).

## The stack as it stands

- `actors/msg-log` (crdt) — ciphertext `Envelope`s only, never plaintext.
- `actors/msg-ctl` (raft) — the MLS delivery service / commit sequencer (one
  Commit per epoch, no forks).
- `actors/msg-directory` (raft) — KeyPackage publish/claim + channel announce.
- `extensions/messenger` (native `.so`, OpenMLS edge) — all crypto local, keystore
  in local redb, never replicated. **P2 turns this into a PVM actor.**
- `actors/chronos` (raft) — clock + bias-resistant committee randomness; the
  messenger hedges its lagged beacon into the MLS CSPRNG `info` (never key material).
- Cross-space substrate already exists (built for the clerk federation):
  `actors/space-bridge` + the hyperspace registry (`host_mappings`,
  `register_remote`, cross-space `resolve`). Phase 5 builds on it.

## Priority (operator-set 2026-06-16)

1. **P2 — PVM-native messenger** (active). Plan is P2.0–P2.5 in
   [`messaging-pvm-native.md`](./messaging-pvm-native.md): mls-rs port behind the
   existing API, a `BOOT_CONTEXT` host seam, a deterministic `CipherSuiteProvider`
   routing every entropy draw through `HostRand` (closes the HPKE-seal
   non-determinism P1 carved out), then no_std the crate and an e2e + RFC-interop
   cutover. Prereqs P0/P1/P3 are all done, so it is unblocked. **P2.0 done** (in-PVM
   ciphersuite-1 crypto is bit-exact vs host RustCrypto + clean across warm restart —
   `vos/tests/crypto_spike_pvm.rs`), **P2.1 `BOOT_CONTEXT` seam done** (fresh per-boot
   token + monotonic epoch + stable device, validated across warm restarts), and the
   **dominant residual unknown — transpiling mls-rs's own code — is RESOLVED**: the
   `_mls_spike` create-group+commit ELF transpiles through `link_elf`
   (`vos/tests/mls_spike_transpile.rs`), confirming the OpenMLS → mls-rs decision.
   **P2.2 done** — the messenger crate runs on mls-rs (Client-centric, custom
   `GroupStateStorage`/`KeyPackageStorage`, deterministic signer, commit auto-apply,
   `write_to_storage`); group-flow / commit-race / eviction gate green. **P2.3 done** too —
   the deterministic `CipherSuiteProvider` (`crypto_provider.rs`) routes all entropy through
   `HostRand` (the seam was `DhType::generate`, which both `kem_generate` and the HPKE ephemeral
   flow through); gate green: bit-identical KEM keypair + HPKE ciphertext + `random_bytes` from
   the same (seed, boot) (`cargo test -p messenger-extension --lib` → 14/14). A **P2.4 down-payment**
   also landed: `ts_ms` is threaded into the MLS KeyPackage/commit Lifetimes, so KeyPackages,
   commits, AND Welcomes are now **byte-identical** given a fixed `(seed, boot, ts)` — full
   byte-determinism closed. **P2.4 done** — the whole crate now builds in two flavors off
   one source (`cfg(target_arch = "riscv64")`): the host `.so` (unchanged) and a no_std
   riscv64 `#[actor]`. `now_ms` reads `SystemTime` on the host / a wire-threaded seam in the
   actor; the boot token comes from the `BOOT_CONTEXT` hostcall in the actor; `store.rs`/
   `crypto_provider.rs` use `spin::Mutex` + `portable_atomic_util::Arc` on the no-atomics
   target; `seed` is mandatory in the actor; mls-rs errors go through `Debug`. **Gate MET:
   the messenger ELF transpiles clean through `link_elf`** (`vos/tests/messenger_transpile.rs`),
   host gate still green (14/14). The messenger stays a host-workspace member. **Next: P2.5**
   (live PVM e2e + RFC-interop OpenMLS↔mls-rs + clean per-channel cutover) — also wire the
   live host/wire `ts_ms` into `set_wire_now_ms` and a durable cross-process `boot_epoch`.
2. **Metadata privacy** (deferred, but the "private" depth — do before claiming
   cross-space is "private"): secret-derived `replication_id`/gossip topic (today
   `blake2b(blob‖name)`, guessable — was parked into Phase 5) + close the directory
   `nickname→KeyPackage` cleartext deanon (review item #7). See `docs/messaging.md`
   Open Problem #2 ("metadata privacy is not provided by the lower layers").
3. **Cross-space (feature Phase 5)** — wire invite/join/replication across the
   bridge + hyperspace substrate; note the documented `register_remote` trust gap.
4. **P4 device-sync** — multi-device per identity + encrypted history archive;
   blocked on device-enrollment infra (not built).
5. **Phase 6 polish** — message padding, epoch suppression, claimed-row GC, doc rewrite.

## Carry-over follow-ups (don't drop)

- **chronos:** a committed multi-node committee integration test (live path is
  only script/demo-verified); registry pubkey-binding to close the enrol
  front-running residual; incremental follower-apply (a raft follower still
  full-replays per applied entry — perf, not correctness). See
  [`chronos-bias-resistance.md`](./chronos-bias-resistance.md) §As-built.
- **branch:** 42 commits, **unpushed**.
- **chronic friction:** the sibling `cipher-clerk` path-dep drift breaks
  `vos --lib` / workspace clippy; tests need it severed by hand (a 4-line
  comment-out + `git checkout vos/Cargo.toml`).
