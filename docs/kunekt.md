# Kunekt — Private-by-Default Collaboration

Kunekt is the headline application that the design of VOS was originally
shaped around. It is a protocol — and a set of built-in actors and
services — for private, decentralized real-time collaboration.

If you are looking for the substrate that runs Kunekt, see
[Part I — Platform](architecture.md). This chapter and the ones below
it are the protocol-level treatment.

## In one paragraph

A **space** is a private collaboration group. Inside a space, all shared
content is represented as **documents** (CRDTs that merge concurrent
edits without conflicts). Document changes propagate via Merkle-CRDTs
(no leader, no consensus on the user's path), are encrypted with a
group ratchet (only members can decrypt — peers and storage backends
see only opaque blobs), and persisted on any available untrusted
backend (relay, DHT, DA layer).

## How it maps onto VOS

| Kunekt concept | VOS mechanism |
|---|---|
| Space | A VOS space (`space_id`, registry, daemon) |
| Document | A `crdt`-mode agent backed by `merkle-crdt` |
| Sync | The standard `crdt` consistency mode in VOS |
| Group encryption | A built-in actor / service group inside the space |
| Persistence backend | Any storage adapter the daemon's persistence layer can target |
| Anonymous credentials | zkPVM-backed proofs (see [zkPVM](zkpvm.md)) |

In short: **Kunekt is a group of actors and services that runs on the
plain VOS runtime.** It does not require a fork or a special build —
it is what you get when you stack the right encryption / authorization
/ persistence policy on top of `crdt`-mode agents.

## Chapters

The remaining chapters are the original Kunekt protocol design. They
predate the VOS-first reframing and still talk in their own vocabulary
in places — that's OK as scaffolding; they will be rewritten to lean
on VOS primitives where they overlap.

- [Vision: The Privacy Gap](privacy-gap.md)
- [Threat Model & Design Principles](threat-model.md)
- [User Journey](user-journey.md)
- [Sync Layer: Merkle-CRDTs](sync.md)
- [Encryption Layer: Group Key Management](encryption.md)
- [Building Blocks](building-blocks.md)
- [Nostr Integration](nostr.md)
- [Privacy Analysis by Layer](privacy-layers.md)
- [Private Economy: Payments, Voting, Governance](private-economy.md)
- [zk-Promises for Anonymous Moderation](zk-promises.md)
- [Security Analysis & Open Questions](security-analysis.md)
