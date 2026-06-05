# Architecture

VOS is a layered system, and the applications on it (starting with
[Messaging](messaging.md)) are layered protocols in turn. Each layer has a
clear responsibility and a clear integration point with existing
technology. Upper layers don't know or care how lower layers work — only
that they fulfill their contract.

> The diagram below is written from the perspective of a full private
> application (messaging being the worked example). Read it as "what an app
> stacks on the platform," not as the platform's own internals — those are
> the rest of Part I.

```
┌─────────────────────────────────────────────────────────────┐
│                     APPLICATION LAYER                        │
│  SDK · Custom CRDTs · Chat · Docs · Marketplace · Voting    │
├─────────────────────────────────────────────────────────────┤
│                     AUTHORIZATION LAYER                      │
│  ZK credentials · zk-promises · Reputation · Rate limits     │
├─────────────────────────────────────────────────────────────┤
│                     DOCUMENT LAYER                           │
│  Spaces · Documents (Automerge, GSet, Counter, ...) · CRDTs │
├─────────────────────────────────────────────────────────────┤
│                     SYNC LAYER                               │
│  Merkle-CRDTs · DAG clock · Anti-entropy · Batching          │
├─────────────────────────────────────────────────────────────┤
│                     ENCRYPTION LAYER                         │
│  OpenMLS · Group keys · Forward secrecy · Key rotation       │
├─────────────────────────────────────────────────────────────┤
│                     STORAGE LAYER                            │
│  Local DB · Nostr relays · DHT · DA layer · PIR · Erasure    │
├─────────────────────────────────────────────────────────────┤
│                     TRANSPORT LAYER                          │
│  Tor · Nym mix net · WebSocket · WebRTC · Cover traffic      │
└─────────────────────────────────────────────────────────────┘
```

Data flows down when writing (app → CRDT op → DAG node → encrypt →
store → transport) and up when reading (transport → fetch → decrypt →
DAG node → CRDT apply → app state).

## Spaces

A space is the top-level unit. It owns:
- An **MLS group** defining membership and encryption keys
- A **membership Merkle tree** for ZK membership proofs
- A set of **documents** (each a CRDT with its own Merkle-DAG)
- A **root document** (CRDT) describing the space: name, settings,
  document list, MLS state, moderation config

The space itself is described by its root document. Everything is
data, everything is a CRDT, everything syncs the same way.

## Documents

Every piece of shared content is a document. A document is a CRDT
paired with a Merkle-DAG history. The CRDT type determines the
semantics:

| Document type | CRDT | Use |
|---|---|---|
| Rich text | Automerge | Collaborative editing |
| Chat channel | Append-only log (GSet) | Messaging |
| Space settings | LWW-Map | Configuration |
| Membership tree | Custom Merkle tree CRDT | ZK membership proofs |
| Moderation log | Append-only log | zk-promises bulletin board |
| Task board | OR-Map of lists | Project management |
| Wallet/ledger | Counter with ZK proofs | Private transactions |
| Proposal + votes | Custom voting CRDT | Governance |

Each document has its own `MerkleCrdt` instance. Documents sync
independently — a peer may subscribe to some documents in a space
but not others.

## Peers

A peer is any device participating in a space. Peers are equal —
there is no leader or primary replica. Each peer:

- Keeps a local encrypted copy of subscribed documents
- Edits freely, even offline
- Syncs with other peers when connectivity allows
- Derives all keys from a single root secret on the device

Sync happens over any transport. The protocol doesn't care how bytes
move — it only needs to exchange encrypted DAG nodes.

## How existing technology maps to the stack

```
Layer            Kunekt component         Existing technology
─────────────────────────────────────────────────────────────
Application      SDK, app templates       (our code)
Authorization    Anon credentials         zk-promises, BBS+, Arkworks
Document         CRDT logic               Automerge
Sync             DAG clock, anti-entropy  merkle-crdt (our crate)
Encryption       Group key management     OpenMLS (RFC 9420)
Storage          Backend adapters         Nostr relays, SQLite, sled
Transport        Anonymity routing        Tor (arti), Nym
```

Each layer is covered in its own chapter — see [Part I](architecture.md)
for the platform layers and [Messaging](messaging.md) for how an
application stacks on top.

## KryptOS mapping

Kunekt implements all three pillars of the
[KryptOS RFP#000](https://codeberg.org/kusama-zk/RFPs/src/branch/main/rfp/000-privacy-os.md):

| KryptOS Pillar | Kunekt Layers |
|---|---|
| Private Communications Protocol | Sync + Encryption + Transport |
| Decentralized Private Data Store | Storage + Encryption + Content Addressing |
| Privacy Application SDK | Application + Document + Authorization |
