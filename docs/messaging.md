# Messaging

Private group messaging, delivered as a set of **actors you install into a
space**. There is no messaging server and no messaging account — a channel is
shared state that replicates across the members' own nodes, the same way every
other document in a VOS space does.

Messaging is the first concrete application built on the VOS primitives, and it
is deliberately general: the same actors back a team chat, a broadcast channel,
a comment thread, or the message bus under a richer app. (A specialized
real-time-collaboration layer — [Kunekt](kunekt.md) — is planned on the same
substrate.)

This chapter is the protocol as **built and running today**. Where a capability
is designed but not yet shipped, it lives under [Future
directions](#future-directions) — clearly separated from what protects you now.

## What it is, in one paragraph

A decentralized, **identity-first, end-to-end-encrypted** group messenger.
Content is encrypted with the **MLS group ratchet** (RFC 9420) on each member's
device; peers, relays, and every shared actor handle ciphertext and public data
only. Membership is keyed to a **verified identity** — a member's cryptographic
key is bound to their space PeerId, so nobody can post or be invited under
someone else's name. The one thing eventual consistency can't provide — which
membership change wins an epoch — is settled by a small per-channel consensus
group; the conversation itself replicates leaderlessly and converges in any order.

## Architecture: the actor stack

A **channel** is not one actor but a small set that split cleanly along the
trust boundary. The device-local `messenger` is the only component that ever
holds plaintext or key material; the rest are replicated and see ciphertext plus
public metadata.

```
            ┌──────────────── this node (device-local, never replicated) ─────────────┐
            │   messenger  (PVM actor, consistency = "local")                          │
  operator ─┼─▶   • MLS credential + ratchet secrets + decrypted history               │
   (CLI)    │     • host-seeded deterministic CSPRNG (the seed never leaves)           │
            │         │  encrypt on send / decrypt on tick                             │
            │         ▼                                                                 │
            │   ciphertext envelopes + MLS commits  (no plaintext, no keys leave here) │
            └─────────┼────────────────────────────────────────────────────────────────┘
                      │  replicated over libp2p (gossip + raft)
        ┌─────────────┼───────────────┬──────────────────┬──────────────────┐
        ▼             ▼               ▼                  ▼                  ▼
  msg-<chan>-log  msg-<chan>-ctl   msg-directory     space-registry       chronos
  (crdt/gossip)   (raft)           (raft)            (crdt)               (raft)
  ciphertext log  MLS commit chain PeerId → KeyPkg   agent catalog +      randomness
  (leaderless)    (sequenced)      + channel list    role grants          beacon
```

| Actor | Consistency | Role |
|---|---|---|
| `messenger` | local (device) | The **E2EE edge**: holds this member's MLS state, encrypts on `send`, decrypts on its poll `tick`. The only place plaintext or keys exist. |
| `msg-<chan>-log` | crdt (gossip) | Leaderless **ciphertext envelope log** — the conversation as opaque, content-addressed blobs. Replicates via [merkle-CRDT](sync.md) and converges in any order. |
| `msg-<chan>-ctl` | raft | Sequenced **MLS commit chain** — linearizes membership changes so exactly one Commit wins per epoch. |
| `msg-directory` | raft | Per-space **verified-PeerId → KeyPackage** map + channel catalog + single-use KeyPackage claims. |
| `space-registry` | crdt | The space's **agent catalog + role grants** — CRDT-replicated, but its mutations are author-signed and replay-verified (the authorization source of truth). |
| `chronos` | raft | Optional verifiable-randomness **beacon** (a freshness hedge folded into the CSPRNG output). |

Two planes, chosen for what each needs. Application messages carry no ordering
constraint MLS can't already handle, so the **log** is a grow-only CRDT that
tolerates any delivery order and heals from any one reachable peer. Membership
Commits *do* need a total order — exactly one Commit may win per MLS epoch — so
the **commit chain** runs on raft. Neither plane ever sees plaintext.

## Group encryption (MLS)

### Why a group ratchet

The naive approach — encrypt each message pairwise to every other member (PGP /
NIP-44 style) — is `O(n)` ciphertexts per message and has no protocol-enforced
notion of membership change. A **group ratchet** instead gives every member the
same symmetric key, derived from a shared secret that ratchets forward on each
change:

- **`O(1)` ciphertext per message** — one encrypted payload, any member decrypts.
- **Forward secrecy** — a leaked key can't decrypt past messages; old epoch
  secrets are dropped as the ratchet advances (VOS keeps a bounded window — up
  to 64 past epochs — so out-of-order delivery still decrypts).
- **Post-compromise security** — a single membership change (or key update)
  mints a fresh epoch secret an attacker can't derive, healing the group.
- **`O(log n)` membership changes** — the ratchet-tree structure re-keys only
  the path from a leaf to the root.

VOS uses **MLS (Messaging Layer Security, RFC 9420)** — the IETF group-key
standard — via the [`mls-rs`](https://github.com/awslabs/mls-rs) implementation.
Each channel is one MLS group.

### MLS in brief

- **Ratchet tree.** Members are leaves of a binary tree; interior nodes hold
  keys derived from their children; the root is the shared group secret. A leaf
  key update re-computes only its root path.
- **Epochs.** Every membership change or key update advances the **epoch**
  (0, 1, 2, …). Each epoch has an `epoch_secret` that a key schedule expands into
  per-message encryption keys and an exporter secret.
- **Proposals & Commits.** A change (Add / Remove / Update) is a *Proposal*; a
  *Commit* bundles proposals and advances the epoch, carrying the tree material
  every member needs to derive the new secret. Only a Commit changes state.
- **Welcome.** When a member is added, the committer also emits a *Welcome* —
  encrypted to the newcomer's KeyPackage — that bootstraps their view of the
  tree at the new epoch.

### How VOS wires it up

The device-local `messenger` holds the MLS `Client` and group state. On `send`
it encrypts the message as an MLS application message and appends the ciphertext
envelope to the channel's **log**. Membership changes become Commits submitted to
the channel's **commit chain** (`msg-ctl`); the Welcome for an added member
*rides the same chain*, and the newcomer recognizes it by **trial-decryption**
on its next poll — the join succeeds only if the Welcome was sealed to a
KeyPackage that member holds. (The on-chain routing token is deliberately
random, not a KeyPackage hash, so a join can't be linked back to an identity.)
A member never receives keys for epochs before it joined, so it can
never decrypt traffic sent before its join epoch — forward secrecy by
construction. A removed member is dropped from the tree by a Commit that re-keys
the group, so it cannot read anything sent afterward.

The ciphersuite is **1**
(`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`): X25519 key agreement,
AES-128-GCM content encryption, SHA-256, Ed25519 signatures — well-supported,
efficient, no RSA baggage.

### Deterministic crypto for a portable actor

The messenger ships as a **deterministic `no_std` RISC-V PVM actor** — one
portable bytecode with no operating system and no OS entropy. Two custom pieces
make MLS run there without weakening it:

- A **host-seeded, forward-ratcheting CSPRNG** (`host_rand`). Its only entropy is
  a 32-byte secret **seed**, provisioned once per device and never replicated;
  every draw is a pure function of `(seed, per-boot token, counter)`. An optional
  public randomness beacon (from `chronos`) may enter *only* as a KDF `info` on
  the output branch — never as key material — so confidentiality rests on the
  seed alone even if the beacon is public.
- A **deterministic `CipherSuiteProvider`** that routes *every* mls-rs entropy
  draw — including the ones inside `kem_generate` and the HPKE ephemeral, not
  just `random_bytes` — through that CSPRNG. Two runs of the same member — same
  seed, boot context, and message timestamp — therefore produce **bit-identical**
  KeyPackages, Commits, and Welcomes: the gate that lets the actor replay
  identically and run bit-for-bit the same on the host and inside the PVM.
  (Distinct members, with distinct seeds, deliberately fork.) The signing
  identity is likewise **seed-derived**, never from `OsRng`, so it is stable
  across restarts.

(This is the technical reason VOS uses mls-rs and not OpenMLS: OpenMLS is
irreducibly `std`, and its HPKE-Seal ephemeral key is drawn by a per-call RNG
that no provider can reach — a deterministic CSPRNG could never cover it.)

## Identity and authentication

Messaging is **identity-first**: every member acts under a **verified space
PeerId**, and their MLS credential is cryptographically bound to it. A member's
own device identity key — the key its PeerId is derived from — signs a **binding
certificate** over `(MLS public key ‖ PeerId ‖ space id)`, and that certificate
travels inside the MLS credential. Any peer validating a leaf recovers the
identity key from the claimed PeerId and checks the signature, so a leaf whose
MLS key isn't bound to the PeerId it claims is rejected. (Whether that PeerId is
an *enrolled* member — the authorization question — is a separate check.)

This closes the impersonation and MITM gaps a nickname-based directory would
leave open:

- **Publishing.** A member publishes KeyPackages under its own verified PeerId,
  not a free-form name.
- **Inviting.** Invite is by PeerId. The inviter claims the target's attested
  KeyPackage from the directory and **refuses** any package whose embedded
  credential binds to a different identity — or to an un-enrolled member — so a
  member can't get itself invited in a victim's place. Out-of-band invites (a
  KeyPackage handed over by link or QR, SimpleX-style) carry the same credential
  and are checked the same way.

The authorization these decisions rest on is itself tamper-evident. The
`space-registry` replicates via CRDT, but its role/membership/agent mutations are
**author-signed** and verified on replay against the genesis anchor, so a member
cannot forge an admin or voter row to grant itself authority. See
[Authorization](authorization.md) and [Identity](identity.md).

## Ordering without a server — and how it compares to Matrix

VOS messaging shares its content substrate with [Matrix](https://matrix.org):
both replicate a room as a content-addressed, hash-linked structure and sync by
"exchange a head, fetch what's missing." The difference is what needs *resolving*.

| | VOS messaging | Matrix |
|---|---|---|
| Message log | grow-only CRDT (merkle-CRDT) | event DAG |
| Room state (membership, roles) | MLS group + role grants | mutable `(type, state_key)` map |
| Conflict resolution | **none for content**; membership by raft quorum | **state-resolution v2** over `auth_events` |
| Identity | verified PeerId | `@user:server` |

Matrix carries a second `auth_events` graph and a notoriously subtle
state-resolution algorithm because its room state is last-writer-wins on single
keys: two members can change the same key concurrently, so a deterministic
resolver must pick a winner — a recurring source of complexity and bugs.

VOS avoids that machinery. Application messages are a **grow-only log**, so there
is nothing to resolve — concurrent posts simply both land, ordered by a
sender-chosen Lamport stamp plus content hash, identically on every replica. The
*one* thing that genuinely needs a total order — which MLS Commit wins an epoch —
is delegated to a small **raft quorum** (`msg-ctl`), a standard, well-understood
consensus, rather than a bespoke state-resolution algorithm. If two members
Commit at the same epoch, the chain accepts one; the other re-issues its change
against the new epoch. The effect is delayed, never lost.

## Using messaging

Everything is driven through the `messenger` actor's CLI verbs (`vosx messenger
…`), which map onto the actors above:

- **`register <nickname>`** — establish this device's identity: derive the
  Ed25519 signer from the CSPRNG seed, bind the MLS credential to the verified
  PeerId, and stock the directory with a few KeyPackages so others can invite you
  by PeerId.
- **`create <channel>`** — install the channel's `log` + `ctl` agent pair if
  absent (admin-gated) and announce it in the directory.
- **`key_package`** — mint a KeyPackage for an out-of-band invite (link / QR).
- **`invite <channel> <peer-id | kp-hex>`** — claim the invitee's attested
  KeyPackage by PeerId (or take a handed one), build an MLS **Add** Commit, and
  submit it to the chain. The Welcome rides the same record.
- **`join <channel>`** — start watching a channel for a Welcome that
  trial-decrypts to one of your published KeyPackages.
- **`send <channel> <text>`** — encrypt as an MLS application message and append
  the ciphertext envelope to the log.
- **`sync`** — force one poll pass now: drain the commit chain to process
  membership changes and pick up Welcomes, then drain the log to decrypt new
  envelopes into node-local history.

The same poll pass runs automatically on a timer (`tick_ms`), so a live node keeps
up without `sync` — the CLI verb just triggers it on demand.

Messaging installs like any other agent set — the channel actors are ordinary
VOS agents declared in a space manifest:

```toml
[[agent]]
name = "messenger"
path = "…/messenger.elf"
consistency = "local"
device_secret = true          # provisions the 32-byte CSPRNG seed on this node
tick_ms = 500
intra_caps = ["msg-*:member", "space-registry:admin"]
```

The `messenger` relays the **operator's** role to the actors it calls, bounded by
`intra_caps`: `member` is the ceiling for posting and committing on the channel
actors, and `space-registry:admin` lets an admin's `create` install a new
channel's agent pair. A caller below the required role is refused downstream — the
messenger grants no authority of its own. The retired single-actor recipe is
retained at `tests/fixtures/legacy-v1/space-msg-a.toml` until this scenario is
rebuilt on the v2 package flow.

## Security

The threat model belongs here rather than in a separate chapter. Three principles
drive it: **encrypted by default** (never opt-in), **verify, don't trust** (no
relay, store, or peer is trusted for confidentiality — every claim is checked
cryptographically), and a **device trust boundary** (your own device is yours;
everything outside it sees ciphertext).

### Adversaries and what stops them

| Adversary | What they can do | Defense |
|---|---|---|
| Network observer | see IPs, sizes, timing on their link | MLS ciphertext everywhere; a metadata-protecting transport is [future work](#future-directions) |
| Untrusted relay / store | log, drop, or reorder the opaque blobs they carry | content-addressed encrypted envelopes; replicate across peers; verify by hash; never trusted for confidentiality |
| Non-member of a channel | hold the ciphertext log | can't decrypt (no epoch keys); sees only envelope metadata (timing, size, epoch) |
| Malicious member | try to impersonate or invite-in-place | credentials are bound to a verified PeerId and checked on every leaf and every invite; forged directory entries are caught |
| Malicious member of the space | forge a role/membership row to escalate | registry mutations are author-signed and replay-verified against the genesis anchor |
| Expelled member | keep keys from their membership era | MLS re-keys on removal (post-compromise security); they derive no future epoch secret |

### What it guarantees

- **Confidentiality** — only current channel members read content (MLS ratchet).
- **Integrity** — tampering is detected (content-addressed envelopes; MLS auth).
- **Authenticity / no impersonation** — a member's key is bound to a verified
  PeerId; a leaf that doesn't match is rejected.
- **Forward secrecy & post-compromise security** — past content survives a key
  leak; future content survives a removal (MLS key schedule).
- **Availability** — the ciphertext log converges with any one honest peer
  reachable and merges offline sends on reconnect; membership changes need their
  channel's raft quorum.

### What it does *not* protect against

Honesty about the perimeter: a **compromised device** (its own keys and plaintext
are exposed — the standard end-to-end assumption); **deanonymization by a fellow
member** — this is identity-first, *not* anonymous, so members know who each other
are; **traffic analysis** by a network observer or a space insider watching log
activity — content and keys stay hidden, but *that* a channel is active, its
membership changes, and envelope timing/sizes are visible to those replicating it,
and there is no mix transport yet; **stylometry** (writing style can deanonymize
content the protocol faithfully hid); **coercion** (no protocol resists
rubber-hose); **quantum adversaries** (today's primitives are pre-quantum); and
**total infrastructure DoS** (if every relay refuses, distant peers can't sync —
local reads continue).

## Future directions

These are designed, and in some cases prototyped, but **not part of what ships
today**. They are the honest answer to "how private can this get?"

- **Anonymous, moderatable membership (zk-promises).** Today the right to post is
  a *role* tied to a verified identity. A stronger variant would let a member
  prove *"I hold a valid, non-banned membership and I'm within my rate limit"* in
  zero knowledge — revealing only a fresh pseudorandom tag, not which member — so
  a moderator can penalize an abusive poster (reputation drop, ban) **without ever
  learning who they are**. This is the classic anonymity-vs-abuse-resistance-vs-
  no-trusted-party trilemma, attacked with committed per-member state + callbacks.
  It needs a per-channel ordering checkpoint (nullifiers and non-membership
  proofs want an agreed current root) and a fast proof system on the hot path — a
  fixed circuit with session-scoped proofs, not the general STARK/PVM prover,
  which is reserved for rare high-stakes actions. See
  [Anonymous Moderation: zk-promises](zk-promises.md).
- **Metadata-protecting transport.** Encryption hides content; identity binding
  fixes *who can act*; neither hides *who talks to whom, when*. The hardest and
  least-mature layer needs mixing / cover traffic / private retrieval. A prototype
  derives per-epoch channel topics from the group's exporter secret so that even
  which channel a packet belongs to is not in the clear. See
  [Transport](transport.md).
- **Multi-device sync.** Each device is already its own MLS leaf with its own
  device-local seed that never leaves it; syncing *history* across a member's own
  devices (a trusted device circle) is the remaining piece.
- **Opt-in history for joiners.** By default a joiner sees the conversation from
  its join epoch on. A space that *wants* new members to read older history
  (a knowledge base) could re-encrypt it under the current epoch as an explicit,
  policy-gated step.

## Further reading

- [Sync Layer: Merkle-CRDTs](sync.md) — the ciphertext log's substrate and anti-entropy
- [Anonymous Moderation: zk-promises](zk-promises.md) — the anonymity roadmap
- [Identity](identity.md) · [Authorization](authorization.md) — verified identity + role grants
- The [`messenger` actor README](../actors/messenger/README.md) — the as-built crate, its protocol, and its threat model
- [Merkle-CRDTs paper](https://arxiv.org/abs/2004.00107) · [zk-promises paper](https://eprint.iacr.org/2024/1260) · [RFC 9420 (MLS)](https://www.rfc-editor.org/rfc/rfc9420.html)
