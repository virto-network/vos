# Kunekt

A protocol for decentralized, private, real-time collaboration.

## What it does

Kunekt lets groups of people work together on shared documents, chat, and data
without relying on a central server. Everything is encrypted so only group members
can read the content. Participants can be online, offline, or on flaky connections
and the system just works — everyone converges to the same state when they sync.

## How it works

A **space** is a private collaboration group. Inside a space, all shared content
is represented as **documents** — text, messages, settings, even the space structure
itself. Each document is a CRDT (a data structure that merges concurrent edits
without conflicts).

The protocol has three layers:

1. **Sync** — Changes propagate between peers using
   [Merkle-CRDTs](https://arxiv.org/abs/2004.00107). Each edit is recorded in a
   hash-linked DAG that acts as a logical clock. Peers exchange a single hash
   (root CID) to discover what's new and fetch only what they're missing. No leader
   election, no consensus, no coordination — any peer can sync with any other peer
   over any transport.

2. **Encryption** — All document content is encrypted using group ratchet keys
   (MLS/Megolm). Only space members can decrypt. Keys rotate automatically on
   membership changes. New members cannot read history from before they joined
   (forward secrecy). Anyone relaying or storing the data sees only opaque blobs.

3. **Persistence** — Encrypted DAG nodes can be stored on any available backend
   (a cloud relay, a DHT, a local database, a blockchain data-availability layer)
   to survive all peers going offline. The storage backend doesn't need to be
   trusted since it only ever sees encrypted, content-addressed data it cannot
   tamper with.

## Design goals

- **No servers** — peers connect directly, relay through untrusted infrastructure,
  or sync via any transport available
- **No coordination** — no leader, no consensus rounds, no single point of failure
- **Private by default** — end-to-end encrypted at the group level, storage and
  relay nodes see nothing
- **Offline-first** — full local editing, seamless merge on reconnect
- **Transport-agnostic** — works over WebRTC, libp2p, Bluetooth, USB, or anything
  that can carry bytes
- **Document-everything** — messages, files, config, access control are all
  documents (CRDTs) linked together

## Architecture

```
┌─────────────────────────────────────────────┐
│                   Space                      │
│                                              │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐     │
│  │ Doc A    │ │ Doc B    │ │ Doc C    │ ... │
│  │ (CRDT)   │ │ (CRDT)   │ │ (CRDT)   │     │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘     │
│       └─────────┬──┴────────────┘            │
│           Merkle-CRDT sync layer             │
│       ┌─────────┴──────────┐                 │
│       │  MLS group keys    │                 │
│       │  (encrypt/decrypt) │                 │
│       └─────────┬──────────┘                 │
└─────────────────┼───────────────────────────┘
                  │ encrypted DAG nodes
    ┌─────────────┼─────────────┐
    ↓             ↓             ↓
 Peer A        Peer B     Storage backend
 (local)      (direct)    (relay/DHT/DA)
```

## Building blocks

| Component | Purpose | Candidate |
|---|---|---|
| Document CRDTs | Conflict-free editing | [automerge](https://automerge.org) |
| Sync layer | Merkle-DAG clock + anti-entropy | [merkle-crdt](../merkle-crdt) |
| Group encryption | Forward-secret group keys | [OpenMLS](https://github.com/openmls/openmls) |
| Peer transport | Connecting browsers and devices | libp2p, WebRTC |
| Persistent storage | Survive all-offline | Any content-addressed store |
