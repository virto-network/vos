# Architecture

This chapter is the map of the **platform**. It shows the layers VOS itself
provides and how they fit together; each has its own chapter in the rest of
Part I. How a full private *application* stacks on top of these layers is a
separate concern, covered in [Messaging](messaging.md).

## The platform, bottom to top

```
┌─────────────────────────────────────────────────────────────┐
│  APPLICATIONS            actors you install into a space      │
│                          (messaging, ledger, …)              │
├─────────────────────────────────────────────────────────────┤
│  zkPVM                   succinct proofs of PVM execution    │
├─────────────────────────────────────────────────────────────┤
│  EXTENSIONS              native host plugins (e.g. gateway)   │
├─────────────────────────────────────────────────────────────┤
│  SPACES & REGISTRY       membership, installed agents, IDs   │
├─────────────────────────────────────────────────────────────┤
│  REPLICATION             ephemeral · local · crdt · raft     │
├─────────────────────────────────────────────────────────────┤
│  PVM RUNTIME             deterministic RISC-V actors + sched │
├─────────────────────────────────────────────────────────────┤
│  PERSISTENCE             redb-backed local state             │
├─────────────────────────────────────────────────────────────┤
│  NETWORK                 libp2p: mDNS · gossipsub · req-resp │
└─────────────────────────────────────────────────────────────┘
```

Each layer has a clear contract; upper layers don't care how lower layers
satisfy it.

| Layer | Responsibility | Chapter |
|---|---|---|
| PVM Runtime | Run actors deterministically so replicas converge bit-for-bit | [Runtime](runtime.md) |
| Replication | Pick the consistency mode per agent | [Replication](replication.md) |
| Persistence | Durable local state | [Persistence](persistence.md) |
| Network | Move bytes between peers | [Transport](transport.md) |
| Spaces & Registry | Group actors, track members and agents | [Documents](documents.md) |
| Extensions | Native host plugins outside the sandbox | [Extensions](extensions.md) |
| Identity | Per-space keys, devices, recovery | [Identity](identity.md) |
| Authorization | Who may call what (roles, ACLs, anon credentials) | [Authorization](authorization.md) |
| zkPVM | Succinct proofs of PVM execution | [zkPVM](zkpvm.md) |

## Actors

The unit of code is an **actor**: ordinary Rust compiled to a small RISC-V
PVM and run inside a host sandbox. Actors are deterministic — two replicas
of the same actor, fed the same messages, reach the same state. That
determinism is what makes replication safe: the network only has to agree
on the *inputs*, never on the *result*. See [Runtime](runtime.md).

## Spaces

A **space** is the top-level unit of collaboration — a per-collaboration
root identified by a content-addressed `space_id`. A space owns:

- a **registry** tracking members and installed agents,
- the **agents** (actor instances) running inside it,
- a **daemon** that owns local persistence and the libp2p endpoint.

Everything inside a space is data, and data is replicated by the mode each
agent chooses. There is no leader and no global ordering across spaces —
only in-space ordering, and only when the chosen mode requires it.

Members onboard by redeeming an invite token: an admin mints a role-scoped
`vos1…` token, and the joiner's daemon redeems it against the space's
bootnode, which grants the joiner's node key a role. Agents are installed
once by an admin — from a genesis recipe applied on the space's first boot,
or a later reconcile against the running space — and replicate from the
registry; a joiner syncs the catalog rather than booting its own manifest,
and each agent reaches a member only if that member's role clears the
agent's sync floor.

Role-scoped sync is access control, not secrecy: every replica that holds
state can leak it, and revocation never claws back already-synced data.
Agents needing real confidentiality use the messenger's answer — an
encrypted payload with gated keys.

## Replication modes

State is replicated per agent, not globally. An agent picks the weakest
mode that is still correct for its data:

| Mode | Guarantee | Use when |
|---|---|---|
| `ephemeral` | none (in-memory) | state needn't outlive the process |
| `local` | durable, single-node | no replication needed |
| `crdt` | eventual, leaderless | edits commute (logs, sets, counters) |
| `raft` | strict, ordered | a single authoritative sequence is required |

The `crdt` mode is backed by the [`merkle-crdt`](sync.md) crate — the same
DAG that underpins [Messaging](messaging.md). See
[Replication](replication.md) for how to choose.

## Where applications fit

An application is just a set of actors installed into a space
([Applications](applications.md)). It composes the platform layers with the
cross-cutting protocol layers it needs — group encryption, anonymous
moderation, metadata-protecting transport. [Messaging](messaging.md) is the
worked example and the place those application-level layers are described.
