# Applications

VOS is a substrate. An **application is a set of actors you install into a
space** — nothing more. The platform supplies the hard parts (deterministic
runtime, replication, identity, encryption, proofs); an application supplies
the logic and the data model, packaged as agents that any space can adopt.

Because applications are just actors over shared CRDT state, they compose:
a space can run messaging, a task board, and a private ledger side by side,
all syncing the same way, all under the same membership and encryption.

## Currently documented

- **[Messaging](messaging.md)** — Private group messaging. The flagship
  application and the first one built end-to-end on the VOS primitives:
  a channel is an append-only CRDT over a Merkle-DAG, content is group-
  encrypted, and the right to post (plus anonymous moderation) is enforced
  by zk-promises rather than by a server. Most apps reuse its building
  blocks.

- **[Private Economy](private-economy.md)** — Payments, voting, and
  governance as private actors: balances and ballots that members can
  transact on and verify without revealing amounts or votes.

## Reserved

- **[Kunekt](kunekt.md)** — A planned, more specialized actor set for
  real-time collaborative applications (shared documents, live cursors).
  It overlaps heavily with Messaging and will build on the same substrate;
  the name is reserved for that future layer rather than for the platform
  as a whole.

## How to add an application here

1. Add a top-level `<app>.md` overview chapter alongside this one.
2. Add a sub-list under it in [`SUMMARY.md`](SUMMARY.md) for any
   per-application chapters.
3. Keep platform-level details (the PVM, replication, networking) in
   Part I and link to them from the application chapters rather than
   re-explaining. Keep cross-app layers (sync, encryption, anonymous
   moderation) in one place and link, so two apps never describe MLS
   twice.
