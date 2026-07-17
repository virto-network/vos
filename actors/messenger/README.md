# messenger

The **E2EE edge of VOS messaging**: a device-local PVM actor that holds this
node's MLS state, encrypts on `send`, decrypts on its poll `tick`, and keeps the
decrypted conversation in node-local state. It is the *only* component in the
messaging stack that ever sees plaintext or key material — every other actor
handles ciphertext and public data only.

This README covers the protocol's **properties** (what it gives you, next) and
the actor's **architecture** (below). [`docs/messaging.md`](../../docs/messaging.md)
sketches the longer-term roadmap — anonymous, moderatable membership and a
metadata-protecting transport — beyond what ships today.

## What it gives you (and what it doesn't)

A **decentralized, identity-first end-to-end-encrypted group messenger**: MLS
(RFC 9420) crypto over a per-space actor substrate, with no messaging server and
no account. The questions that decide whether it fits your use case:

- **Is content end-to-end encrypted, with what?** Yes — RFC 9420 **MLS** (via
  mls-rs), ciphersuite 1 (X25519 · AES-128-GCM · SHA-256 · Ed25519). Encrypt and
  decrypt happen only on-device (this actor); peers, relays, and every other
  actor handle ciphertext and public data only.
- **Forward secrecy & post-compromise security?** Both, from the MLS key
  schedule. A key leak doesn't expose past messages (forward secrecy); removing a
  member rekeys the group so they can't read future messages (post-compromise
  security). A joiner never decrypts traffic from before its join epoch.
- **Can someone impersonate me?** No — identity-first. Each member's MLS
  credential is bound to a **verified space PeerId** by an operator-signed
  certificate carried in the credential; an inviter refuses any KeyPackage whose
  credential doesn't match the expected PeerId. So a member can't publish a key
  under someone else's identity or MITM an invite. (It is *not* anonymous — your
  PeerId is known to the group.)
- **Who do I trust? Is there a server?** No messaging server. A *space* is a set
  of actors replicated across members' own nodes over libp2p — a leaderless CRDT
  for the ciphertext log, raft quorums for the sequenced planes (membership
  commits, directory, registry). Secret key material is device-local and never
  replicated, and registry mutations that grant roles or install agents are
  **author-signed**, so a member can't forge admin/voter rows.
- **Metadata — who sees who talks to whom?** Content and keys are hidden from
  *all* infrastructure, but the ciphertext log and commit chain replicate across
  the space's nodes, so anyone in the space sees channel **activity** — that a
  channel exists, its membership changes, envelope timing and sizes — while only
  channel members decrypt content and authorship. There is **no metadata-hiding
  transport yet** (no mixnet / cover traffic), so a network observer sees libp2p
  traffic patterns. Metadata-privacy work (epoch-scoped topics, …) is roadmap.
- **Multi-device?** Each device is its own MLS leaf with its own device-local
  seed that never leaves it. Cross-device history sync is not yet built.
- **Availability / offline?** The ciphertext log is a leaderless CRDT: it
  converges with any one honest peer reachable and merges offline sends on
  reconnect. Membership changes need their channel's raft quorum.
- **What it does *not* protect against:** a compromised device (your own device
  reads your plaintext — the standard end-to-end assumption); deanonymization by
  a fellow space member (identity-first, not anonymous); traffic analysis by a
  network observer (no mix transport yet); pre-quantum cryptanalysis (today's
  primitives are classical); and total relay DoS (local reads continue, sync
  stalls).

## Trust boundary

```
            ┌──────────────────── this node (device-local) ────────────────────┐
            │                                                                   │
  operator ─┼─▶  messenger (PVM actor, consistency = "local")                   │
  (CLI)     │      • MLS credential + ratchet secrets + plaintext history       │
            │      • host-seeded deterministic CSPRNG (the seed never leaves)   │
            │            │  encrypt / decrypt at the edge                       │
            │            ▼                                                       │
            │      ciphertext envelopes + MLS commits (no plaintext, no keys)   │
            └────────────┼──────────────────────────────────────────────────────┘
                         │  replicated over libp2p (gossip + raft)
        ┌────────────────┼───────────────┬──────────────────┬──────────────────┐
        ▼                ▼               ▼                  ▼                  ▼
  msg-<chan>-log   msg-<chan>-ctl    msg-directory     space-registry        chronos
  (crdt / gossip)  (raft)            (raft)            (raft)                (raft)
  ciphertext log   MLS commit chain  PeerId → KeyPkg   agent catalog +       randomness
  (leaderless)     (sequenced)       + channel list    auth grants           beacon
```

Everything inside the dashed box is device-local and **never replicated**:
signature keys, ratchet secrets, the CSPRNG seed, and decrypted history. The
operator of *this* node can read this node's plaintext — the standard end-to-end
assumption that your own device is yours. Peers, relays, and the replicated
actors below the box only ever handle ciphertext.

## Related actors and how the messenger talks to them

All interaction is over the VOS actor ask/tell path (the typed clients live in
[`src/clients.rs`](src/clients.rs)). The messenger resolves each target by name
through the registry, then asks it.

| Actor | Consistency | Role | Messenger calls (`clients.rs`) |
|---|---|---|---|
| `msg-<chan>-log` | crdt (gossip) | Leaderless ciphertext **envelope log** — the conversation as opaque bytes. | `log_post` (append an encrypted envelope), `log_history` (read) |
| `msg-<chan>-ctl` | raft | Sequenced **MLS commit chain** — linearizes membership changes so exactly one Commit wins each epoch. | `ctl_commit` (submit a Commit), `ctl_commits` (drain the chain) |
| `msg-directory` | raft (per-space) | **verified PeerId → KeyPackage** map + channel catalog + single-use KeyPackage claims. | `dir_publish_kp`, `dir_claim_kp`, `dir_release_kp`, `dir_announce_channel`, `dir_channels` |
| `space-registry` | raft | The space's **agent catalog** + auth grants. | `resolve` (name → ServiceId), `reg_agent_by_pattern` (find a channel-pair template), `reg_install` (install a channel's agent pair) |
| `chronos` | raft | Verifiable-randomness **beacon** (optional). | `chronos_beacon` (latest finalized round → CSPRNG hedge) |

A **channel** is the pair `msg-<chan>-log` + `msg-<chan>-ctl`. The messenger
addresses them by channel name (`log_agent_name`/`ctl_agent_name` in
[`src/lib.rs`](src/lib.rs)). The first channel's pair is installed from the
manifest; `messenger create` clones that pair's program rows to install further
channels at runtime (the admin-gated `reg_install`).

## Message flows

- **`register <nickname>`** — establish this node's identity: derive the Ed25519
  signer from the CSPRNG seed (deterministic, reproducible), set the MLS
  credential, and stock the directory with a few KeyPackages so others can invite
  this member by their verified PeerId (`dir_publish_kp`).
- **`create <channel>`** — install the channel's `log`/`ctl` agent pair if absent
  (`reg_install`, admin) and announce it (`dir_announce_channel`).
- **`key_package`** — mint a KeyPackage for out-of-band handoff (link/QR), the
  SimpleX-style invite path.
- **`invite <channel> <peer-id|kp-hex>`** — claim the invitee's directory
  KeyPackage by verified PeerId (`dir_claim_kp`, single-use) or take a handed
  one, build an MLS **Add** commit,
  and submit it to the chain (`ctl_commit`). The **Welcome rides the commit
  chain**; the invitee recognizes it by trial-decryption on its next `tick`.
- **`join <channel>`** — start watching a channel for a Welcome addressed to one
  of this member's published KeyPackages.
- **`send <channel> <text>`** — encrypt the message as an MLS application message
  and append the ciphertext envelope to the log (`log_post`).
- **`tick`** (periodic, `tick_ms`) — the poll loop ([`src/tick.rs`](src/tick.rs)):
  drain the commit chain (`ctl_commits`) to process membership changes and pick up
  Welcomes, then drain the log (`log_history`) to decrypt new envelopes into
  node-local `channels` state. Forward secrecy is enforced through the log's epoch
  gate, so a member never decrypts traffic sent before its join epoch.

## Cryptography

RFC 9420 MLS via **mls-rs** (AWS), ciphersuite 1
(`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`). The crate must also build as a
*deterministic no_std riscv64 PVM actor*, which drives two custom pieces:

- **`host_rand.rs` — a host-seeded forward-ratcheting CSPRNG.** A PVM actor has no
  OS entropy, so MLS randomness comes from a CSPRNG whose only entropy is a
  32-byte secret seed; output is a pure function of `(seed, boot context, draw
  counter)`. Two randomness planes are kept strictly apart: the **secret seed**
  is the only confidentiality root (HKDF IKM), and an optional **public beacon**
  (the chronos hedge) may enter *only* as HKDF `info` on the output branch — never
  the IKM, salt, or ratchet (RFC 9180 §9.7.5). So confidentiality rests on the
  seed alone even if the beacon is known. State uses `RefCell`/`Cell` —
  single-threaded interior mutability, no lock.
- **`crypto_provider.rs` — a deterministic `CipherSuiteProvider`.** mls-rs draws
  entropy *inside* `kem_generate`/`hpke_seal` (not just `random_bytes`), so the
  provider overrides `DhType::generate` (the X25519 KEM + HPKE ephemeral) and
  `random_bytes` to route every draw through `HostRand`. Result: two providers
  from the same `(seed, boot context)` emit **bit-identical** KeyPackages,
  commits, and Welcomes — the reproducibility the actor relies on across restarts.

The signing identity is **seed-derived**, not drawn from `OsRng`
(`mls::derive_signer`), so it is stable across restarts and reproducible from the
seed alone.

Why mls-rs and not OpenMLS: OpenMLS is irreducibly `std` (a non-optional `rayon`
the PVM target would pull, `SystemTime`, `std::collections`) and, decisively, its
HPKE-Seal ephemeral key is drawn by hpke-rs's own per-call RNG — a seam
structurally unreachable through the provider, so a deterministic CSPRNG could
never cover it. mls-rs makes std/rayon optional and routes both `kem_generate`
and the HPKE ephemeral through `DhType::generate`. (Full rationale in
`src/lib.rs` module docs.)

## State & persistence

The `#[actor]` state ([`src/lib.rs`](src/lib.rs)) is flat and device-local:
`nickname`, `signature_key` (public), `peer_id`/`binding_cert`/`space_id` (the
verified space identity bound by `bind_identity`), `mls_store` (the mls-rs
storage providers, snapshotted to bytes — see [`src/store.rs`](src/store.rs)),
`csprng_seed` (the secret root), `published_kp_count`, and `channels` (decrypted
history). It
persists in the node-local `consistency = "local"` redb and survives daemon
restarts; nothing here is ever replicated.

The `csprng_seed` is provisioned once via the daemon's **`device_secret`**
mechanism (32 bytes of host OS entropy delivered by a `seed` message, held in a
node-local sidecar) — never carried in the replicated `AgentConfig.storage`.

> **Cost note.** Each mutating MLS op restores the full store, rebuilds the
> `Client` (re-derives the signer, reconstructs both providers + the CSPRNG), and
> re-serializes the whole store — `O(total MLS state)` per dispatch. Sound at
> current group sizes; a scalability ceiling for a node in many or large groups.
> The `Client` can't be cached across dispatches because actor state must
> round-trip to bytes between messages.

## Authority

The messenger relays the **operator's** role to the actors it calls, bounded by
its manifest `intra_caps = ["msg-*:member", "space-registry:admin"]`: `member` is
the ceiling for post/commit on the channel actors (and the `msg-*` wildcard
covers channels created at runtime), and `space-registry:admin` lets an admin's
`messenger create` install a new channel's agent pair. A caller below the
required role is refused downstream — the messenger grants no authority of its
own.

## Build & test

```sh
# host (unit tests + the two-node e2e harness)
cargo test --manifest-path actors/messenger/Cargo.toml

# the commit-race retry + transpile/link gates live in vos
cargo test -p vos --test messenger_pvm --test messenger_transpile

# the PVM actor ELF (deterministic no_std riscv64 build)
just build-messenger-actor          # = cd actors/messenger && cargo +nightly actor
```

The crate is its own workspace; the ELF lands in
`actors/messenger/target/riscv64em-javm/release/messenger.elf`. The transpile
gate (`cargo test -p vos --test messenger_transpile`) checks it links through
`grey_transpiler::link_elf`; `messenger_pvm` checks it *executes* in a bare
runtime. Manifests load it as a device-local agent:

```toml
[[agent]]
name = "messenger"
path = "../actors/messenger/target/riscv64em-javm/release/messenger.elf"
consistency = "local"
device_secret = true
tick_ms = 500
intra_caps = ["msg-*:member", "space-registry:admin"]
```

See `examples/space-msg-{a,b}.toml` for a runnable two-node demo
(`just demo-msg-procs`).
