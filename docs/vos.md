# Introduction

## A new kind of internet, made of secret spaces

The internet was built without privacy. Even when content is encrypted,
*everything around it* leaks — who you talk to, when, how often, what
groups you belong to — because the servers that route and store your data
have to see it to do their job.

VOS is a bet on a different shape: an internet made of **spaces** —
private, sovereign groups that live on their members' own devices. Inside a
space, people message, collaborate, store data, transact, and govern, and
the infrastructure carrying the bytes is treated as an untrusted relay that
learns as little as cryptography allows. No space depends on a server
somebody owns.

This book has two depths. If you want the **vision and the applications**
— private messaging and beyond — start with [Applications](applications.md).
If you want **how it's built**, read on: the rest of this introduction and
[Part I](architecture.md) are the platform.

## VOS, the platform

VOS is a peer-to-peer operating system for collaborative, replicated
applications.

It runs deterministic actors on a JAM-aligned PVM (RISC-V) and replicates
their state across nodes using either CRDTs (eventual consistency) or
Raft (strict consistency). **Spaces** group actors into per-collaboration
roots that converge automatically when peers come online — with no central
server and no coordination protocol on the user's critical path.

## Why VOS

Most collaborative software still routes through a server somebody owns.
The server holds the keys to who can read, who can write, and what the
canonical state is. When the server goes away — or when its operator's
incentives drift — the application goes with it. That model is convenient,
but it leaves users with neither privacy nor durability.

VOS takes the opposite default. State lives on the participating peers,
encryption keys live with the participants, and any storage backend is
treated as an untrusted relay for content-addressed bytes. Coordination
is replaced by deterministic actors and the right replication strategy
per piece of state.

## What VOS provides

- **A deterministic actor runtime.** Actors are ordinary Rust compiled
  to a small RISC-V PVM. The host runs them inside a sandbox so two
  replicas of the same actor under the same `replication_id` converge
  bit-for-bit.
- **Per-agent consistency modes.** Pick `ephemeral`, `local`, `crdt`,
  or `raft` per agent depending on whether the state is commutative,
  strictly sequenced, or doesn't need to outlive the process.
- **Spaces.** A space is a per-collaboration root identified by a
  content-addressed `space_id`. Inside the space, actors talk to each
  other, the registry tracks members and installed agents, and the
  daemon owns the local persistence.
- **A peer-to-peer network layer.** libp2p transport with mDNS, gossipsub,
  and request-response baked in. Multi-node spaces work over loopback,
  LAN, or the open internet.
- **A built-in CLI** (`vosx`) for running the daemon, dialing it from
  one-shot client commands, and reconciling TOML manifests against the
  live registry.
- **A zkPVM** for producing succinct proofs of PVM execution, used to
  push trust-minimized computation off the critical path.

## What VOS is not (yet)

- Not a cloud platform with managed services.
- Not a blockchain — there's no global ordering of all events. Only
  in-space ordering, and only when the chosen consistency mode requires it.
- Not a framework that hides the network. Replication, consistency, and
  identity are first-class choices in your manifest, not magic.

## Where to go next

- **[Architecture Overview](architecture.md)** — the layers and how they
  fit together.
- **[Spaces, Actors & Documents](documents.md)** — the unit of collaboration.
- **[PVM Runtime](runtime.md)** — what runs your code.
- **[Replication: CRDT vs Raft](replication.md)** — picking the right
  consistency mode per agent.
- **[Applications](applications.md)** — what you install into a space.
  Start with **[Messaging](messaging.md)**, the flagship private-by-default
  application built on the VOS primitives.
