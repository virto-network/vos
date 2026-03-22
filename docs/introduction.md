# Introduction

Kunekt is a protocol for building a private-by-default internet.
It implements the [KryptOS Privacy OS](https://codeberg.org/kusama-zk/RFPs/src/branch/main/rfp/000-privacy-os.md)
vision: a unified system where people communicate, collaborate, store
data, transact, and govern — all without exposing who they are, what
they're doing, or who they're doing it with.

## The problem

The internet was built without privacy. Every message, document, and
transaction leaves a trail — who sent it, who received it, when, how
often, from where. Encryption hides content but metadata remains:
connection graphs, timing patterns, access logs, group membership.

Existing tools solve pieces: Signal encrypts messages, CRDTs enable
offline collaboration, zero-knowledge proofs enable anonymous
credentials. But no system combines them into a coherent whole where
privacy is the default at every layer.

## What Kunekt is

Kunekt is three things unified under one protocol:

1. **A private communications protocol.** Groups of people collaborate
   on shared documents, chat, and data in real-time. Content is
   end-to-end encrypted. Members can be anonymous. No central server
   coordinates anything.

2. **A decentralized private data store.** Encrypted, content-addressed
   data distributed across untrusted backends. Users own their data.
   Storage providers can't read it, can't correlate access patterns,
   can't even tell what kind of data it is.

3. **A privacy application SDK.** Developers build private-by-default
   applications — chat, documents, marketplaces, voting, anything —
   using Kunekt as a library. The protocol handles encryption, sync,
   anonymity, and storage. The developer writes application logic.

## Core concepts

A **space** is a private collaboration group. Inside a space, all shared
content is represented as **documents**. Each document is a CRDT — a data
structure that merges concurrent edits without conflicts.

Participants can be online, offline, or on flaky connections. Everyone
converges to the same state when they sync. There is no leader election,
no consensus rounds, no single point of failure.

## Design principles

These come directly from the KryptOS philosophy:

- **Privacy as default** — protection applies automatically, not through
  opt-in. Encryption, anonymity, and metadata protection are on by
  default. Users choose to reduce privacy (for convenience), never the
  reverse.
- **Cryptographic verification** — zero-knowledge proofs replace
  institutional trust. You don't trust the server, the relay, or the
  storage provider. You verify mathematically.
- **System integration** — components function as cohesive layers, not
  isolated tools. Sync, encryption, anonymity, storage, and credentials
  are designed together so there are no gaps between them.
- **Developer accessibility** — building a private application should not
  require cryptography expertise. The SDK abstracts the complexity.
- **Open standards** — all protocols, specifications, and code are
  community-driven. No vendor lock-in, no proprietary components.

## Building on what exists

Kunekt is not built from scratch. It composes proven technologies:

| Layer | Technology | Why |
|---|---|---|
| Sync | [Merkle-CRDTs](https://arxiv.org/abs/2004.00107) | Leaderless replication with efficient anti-entropy |
| Document CRDTs | [Automerge](https://automerge.org) | Mature conflict-free editing for text, JSON, etc. |
| Group encryption | [OpenMLS](https://github.com/openmls/openmls) | IETF-standard group key agreement with forward secrecy |
| Anonymous credentials | [zk-promises](https://eprint.iacr.org/2024/1260) | Anonymous moderation with accountable consequences |
| Relay infrastructure | [Nostr](https://nostr.com) relays | Thousands of deployed dumb-storage servers |
| Network anonymity | [Nym](https://nymtech.net) / Tor | Metadata-resistant transport |
| Zero-knowledge proofs | Groth16 / PLONK / Nova | Anonymous credentials, private transactions, verifiable computation |
| Content addressing | CID (hash-based) | Self-verifying, location-independent, deduplicated storage |

Each technology is mature on its own. Kunekt's contribution is the
integration — making them work together as a seamless private-by-default
system with no gaps between layers.

See [Building Blocks](./building-blocks.md) for details on each
technology and how it integrates, and [Development Phases](./roadmap.md)
for the order we build them in.
