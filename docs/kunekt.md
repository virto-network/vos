# Kunekt — Real-Time Collaboration (reserved)

> **Status: reserved / planned.** Kunekt is not a separate platform and no
> longer names the whole project. It is reserved for a future, specialized
> set of actors for **real-time collaborative applications** — shared rich-
> text and structured documents, live cursors and presence, fine-grained
> co-editing — built on the same substrate as [Messaging](messaging.md).

## Where it came from

The VOS design was originally shaped around "Kunekt," a private-by-default
collaboration protocol. As the work progressed, that single application
split into two things:

- **The platform** — the deterministic actor runtime, replication,
  identity, encryption, and proofs — which became **VOS**
  ([Part I](architecture.md)).
- **The applications** — the actors you install into a space — of which
  the general one is now [Messaging](messaging.md).

Kunekt is what remains once you subtract those: the *specialized* real-time
collaboration layer that goes beyond messaging.

## How it will relate to Messaging

Messaging and Kunekt share almost everything below the application logic —
the [Merkle-CRDT sync](sync.md) layer, [group encryption](messaging.md#group-encryption-mls),
and [anonymous moderation](zk-promises.md). Kunekt adds what real-time
co-editing specifically needs:

- richer document CRDTs (e.g. Automerge for collaborative text/JSON) rather
  than an append-only message log;
- low-latency presence and awareness (cursors, selections);
- per-keystroke batching tuned for live editing.

Until Kunekt is built, treat [Messaging](messaging.md) as the canonical
example of how applications sit on VOS. The deeper protocol chapters
(sync, encryption, threat model, privacy analysis) live under Messaging and
apply equally to a future Kunekt.
