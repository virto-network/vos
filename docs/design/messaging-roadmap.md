# Messaging roadmap & status (branch `messaging`)

Single bird's-eye index for the private-messaging work, so the detailed plans —
spread across two design docs + memory — don't get lost. Last updated 2026-06-22.

**The promise:** an end-to-end *private* communications protocol with *cross-space*
private messaging. Decomposed:

| Part | State |
|---|---|
| Real E2EE content privacy (MLS, ciphertext-only replication, PCS) | ✅ done |
| The single-space messaging substrate (3 actors + edge crypto) | ✅ done (feature Phases 1–4) |
| PVM-native messenger (mls-rs port, cut over from host `.so` to a PVM actor) | ✅ done (P2 + P2.5; 2-node e2e GREEN) |
| Verifiable randomness the MLS CSPRNG hedges (the `chronos` clock+beacon) | ✅ done + bias-resistant (Phase D v1) |
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
P0 immutable-local ✅ · P1 host-seed ratcheting CSPRNG ✅ · **P2 + P2.5 PVM-native
messenger port ✅** (messenger on mls-rs with a deterministic host-seeded provider;
builds as a no_std riscv64 `#[actor]` whose ELF transpiles through `link_elf`; cut
over from a host `.so` `[[extension]]` to a `consistency="local"` PVM `[[agent]]`;
full 2-node e2e GREEN under the default JIT recompiler) · P3 verifiable-randomness
actor ✅ (= `chronos`, hardened by
[`chronos-bias-resistance.md`](./chronos-bias-resistance.md)) · P4 trusted device-sync
(blocked on device enrollment).

## The stack as it stands

- `actors/msg-log` (crdt) — ciphertext `Envelope`s only, never plaintext.
- `actors/msg-ctl` (raft) — the MLS delivery service / commit sequencer (one
  Commit per epoch, no forks).
- `actors/msg-directory` (raft) — KeyPackage publish/claim + channel announce.
- `messenger` (a `consistency="local"` PVM `[[agent]]`, mls-rs edge) — all crypto
  local, keystore in local redb, never replicated. Cut over from the old native `.so`
  `[[extension]]` to a no_std riscv64 PVM actor (P2/P2.5); a deterministic host-seeded
  `CipherSuiteProvider` routes every entropy draw through `HostRand`.
- `actors/chronos` (raft) — clock + bias-resistant committee randomness; the
  messenger hedges its lagged beacon into the MLS CSPRNG `info` (never key material).
- Cross-space substrate already exists (built for the clerk federation):
  `actors/space-bridge` + the hyperspace registry (`host_mappings`,
  `register_remote`, cross-space `resolve`). Phase 5 builds on it.

## Priority (operator-set 2026-06-22)

1. **Cross-space (feature Phase 5)** (active) — wire invite/join/replication across
   the bridge + hyperspace substrate; note the documented `register_remote` trust gap.
2. **Metadata privacy** (deferred, but the "private" depth — do before claiming
   cross-space is "private"): secret-derived `replication_id`/gossip topic (today
   `blake2b(blob‖name)`, guessable — was parked into Phase 5) + close the directory
   `nickname→KeyPackage` cleartext deanon (review item #7). See `docs/messaging.md`
   Open Problem #2 ("metadata privacy is not provided by the lower layers").
3. **P4 device-sync** — multi-device per identity + encrypted history archive;
   blocked on device-enrollment infra (not built).
4. **Phase 6 polish** — message padding, epoch suppression, claimed-row GC, doc rewrite.

**Done (P2 + P2.5 — PVM-native messenger).** The messenger is now a
`consistency="local"` PVM `[[agent]]`, cut over from the old native `.so`
`[[extension]]`: mls-rs port behind the existing API, a `BOOT_CONTEXT` host seam, and a
deterministic `CipherSuiteProvider` routing every entropy draw through `HostRand` (closes
the HPKE-seal non-determinism P1 carved out — KEM keypair, HPKE ciphertext, and
`random_bytes` are bit-identical given a fixed `(seed, boot)`; `ts_ms` threaded into the
MLS Lifetimes makes KeyPackages, commits, and Welcomes byte-identical given `(seed, boot,
ts)`). The whole crate builds in two flavors off one source (`cfg(target_arch =
"riscv64")`): the host `.so` and a no_std riscv64 `#[actor]` whose ELF transpiles clean
through `link_elf`. The full 2-node e2e (`two_nodes_exchange_e2ee_messages`: libp2p +
raft + MLS create/join/commit + bidirectional E2EE + member removal) is GREEN under the
default JIT recompiler. The old "PVM guest-stack overflow" blocker was a misdiagnosis —
four codegen bugs (three in grey-transpiler: CALL_PLT `pending_load_imm` leak,
`load_imm`+ALU self-alias / non-commutative-shift mis-fuse, `load_imm`+load `rd!=rs1` with
missing `address_map`; one in the javm JIT recompiler: a variable shift whose destination
is `phi[12]=RCX` clobbered the shift count) — all fixed in jar (branch
`fix/pvm-transpiler-codegen`), merged to `olanod/jar` master at `c91e83c1`; vos pins that
commit.

## Carry-over follow-ups (don't drop)

- **chronos (v1 D0–D4 landed):** deterministic slot clock + ECVRF-over-Ristretto255
  committee commit-reveal randomness (ECVRF-RISTRETTO255-SHA512 — SHA-512 is the
  ciphersuite hash, not blake2b). The beacon-hedge fold is now WIRED:
  `mls::build_client_hedged` folds `chronos.latest_final()` — domain-bound via blake2b
  to its round — into the MLS CSPRNG's HKDF OUTPUT branch only (never seed/salt/ratchet,
  so confidentiality still rests on the secret seed; RFC 9180 §9.7.5); absent chronos =>
  None => byte-identical to before. Open follow-ups: a committed multi-node committee
  integration test (live path is only script/demo-verified); registry pubkey-binding to
  close the enrol front-running residual; incremental follower-apply (a raft follower
  still full-replays per applied entry — perf, not correctness). See
  [`chronos-bias-resistance.md`](./chronos-bias-resistance.md) §As-built.
- **fixtures retired:** the feasibility-spike actors (`actors/_mls_spike`,
  `actors/_crypto_spike`, `actors/_chronos_crypto_spike`) were deleted — coverage is
  subsumed by `vos/tests/messenger_transpile.rs`, `vos/tests/messenger_pvm.rs`, and
  `vos/tests/chronos_transpile.rs` over the real crates.
- **branch:** `messaging`, squashed to 6 feature commits, **pushed to origin**
  (codeberg; PR open).
- **chronic friction:** the sibling `cipher-clerk` path-dep drift breaks
  `vos --lib` / workspace clippy; tests need it severed by hand (a 4-line
  comment-out + `git checkout vos/Cargo.toml`).
