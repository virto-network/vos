# Messaging

Private group messaging, delivered as a set of **actors you install into a
space**. There is no messaging server and no messaging account — a channel
is just shared state that converges across the members' devices, the same
way every other document in a VOS space does.

Messaging is the first concrete application built on the VOS primitives.
It is deliberately general: the same actors back a team chat, a public
broadcast channel, a comment thread, or the message bus underneath a
richer app. (The more specialized real-time collaboration layer —
[Kunekt](kunekt.md) — is planned on top of this same substrate.)

## In one paragraph

A **channel** is an append-only log CRDT backed by a
[Merkle-DAG](sync.md). Each message is a node whose children are the
log's current heads, so causal order ("this is a reply to that") is
encoded in the graph itself — no clock, no sequence server. Message
payloads are [end-to-end encrypted](encryption.md) to the space's group,
so peers and storage backends see only opaque, content-addressed blobs.
The right to post — and the ability to be moderated while staying
anonymous — is enforced by [zk-promises](zk-promises.md) credentials
rather than by a server checking an account.

## The layered design

Messaging is not one protocol but a stack of independent layers, each
solving one privacy problem and each documented on its own page. The
contribution is the *composition* — privacy holds only if the layers are
designed together, with no gaps between them.

| Layer | Goal | Mechanism | Status |
|---|---|---|---|
| **Content** | only members can read | MLS group ratchet ([Encryption](encryption.md)) | planned |
| **Ordering** | leaderless, convergent history | Merkle-CRDT DAG ([Sync](sync.md)) | built (`merkle-crdt`) |
| **Authorization** | anonymous *yet* moderatable | zk-promises ([Anon Moderation](zk-promises.md)) | design + primitives |
| **Metadata** | hide who-talks-to-whom, when | mix transport / cover traffic ([Transport](transport.md)) | open research |

Writing flows down the stack (message → CRDT op → DAG node → encrypt →
store → transport); reading flows back up. See [Privacy Analysis by
Layer](privacy-layers.md) for exactly what each layer hides from the one
below it, and the [Threat Model](threat-model.md) for the adversaries.

## Why a DAG — and how it compares to Matrix

Messaging shares its core data structure with the [Matrix
protocol](https://matrix.org): both represent a room as a content-addressed,
hash-linked DAG of events, where each new event points at the current
"heads" (Matrix calls them *forward extremities*; we call them *roots*).
Sync in both is "exchange a head hash, fetch what's missing, skip any
sub-graph you already have."

The difference is what an event *means*, and it is the whole reason this
design can be simpler.

| | VOS messaging | Matrix |
|---|---|---|
| Node identity | `CID = hash(payload ‖ children)` | `event_id = hash(redacted event)` |
| Causal links | `children` (current roots) | `prev_events` |
| Auth links | — (none) | `auth_events` (a second edge set) |
| State model | CRDT fold over causal order | mutable `(type, state_key)` map |
| Conflict resolution | **none needed** (CRDTs commute) | **state resolution v2** |
| Identity | anonymous credential | `@user:server` |

Matrix carries a *second* graph of `auth_events` and a notoriously subtle
**state-resolution** algorithm. It needs them because Matrix room state
(membership, power levels, topic) is **last-writer-wins on single-valued
keys**: two members can concurrently change the same key, so a
deterministic, abuse-resistant resolver must pick a winner. That resolver
has been a recurring source of complexity and security bugs.

VOS messaging avoids that machinery entirely by a single design choice:
**all mutable room state is expressed as CRDTs**, so concurrent writes
*merge* instead of *conflict*. The message log is grow-only; membership is
an OR-Set; moderation facts are monotonic. A plain causal fold (the
`merkle-crdt` crate's `Payload::apply`) is then sufficient — there is
nothing to "resolve."

That leaves exactly one hard requirement Matrix solves with `auth_events`:
**permissions and abuse-resistance against hostile participants.** Instead
of server-enforced power levels, VOS messaging moves that to the
authorization layer — [zk-promises](zk-promises.md) — which buys something
Matrix cannot offer: enforcement over participants who are *anonymous and
unlinkable*.

## Membership and moderation without identity

The usual trilemma in messaging is **anonymity vs. abuse-resistance vs.
no-trusted-party** — pick two. zk-promises is a serious attempt at all
three:

- Each member holds a private **zk-object** — their membership /
  reputation / rate-limit / ban state — committed (not revealed) to a
  bulletin board.
- To post, a member proves in zero knowledge: *"I hold a valid,
  non-banned membership for this channel, I've scanned my pending
  callbacks recently, and I'm within my rate limit"* — revealing only a
  fresh pseudorandom tag, not which member.
- A moderator who sees abuse posts a **callback** against the offending
  message's ticket. The offender is forced to fold that penalty
  (reputation drop, ban) into their own state before they can post again
  — **without the moderator ever learning who they are.** This is
  *asynchronous negative feedback*: you can penalize an anonymous,
  currently-offline poster, and they cannot evade it without abandoning
  their standing.
- Anti-Sybil falls out of the same machinery: reputation-scaled rate
  limiting throttles fresh/low-reputation identities, and minting a new
  membership carries an entry cost (invite, proof-of-personhood, or
  stake).

This replaces Matrix's `auth_events` + power levels with a privacy-
preserving equivalent. See [Anonymous Moderation](zk-promises.md) for the
mechanism and [Authorization](authorization.md) for how it sits in the
platform.

## What VOS already provides

Messaging is less greenfield than it looks — the substrate exists today:

- **The DAG** is the shipped [`merkle-crdt`](sync.md) crate (leaderless
  log CRDT, content-addressed nodes, anti-entropy sync). The chat example
  in that crate is the skeleton of a channel.
- **Replication** runs over libp2p with gossipsub push and
  request-response pull — the [`crdt` consistency mode](replication.md).
- **Proofs ship cheaply.** Large STARKs move by 32-byte content address
  over libp2p via the proof-blob CAS, so a channel can distribute
  authorization proofs without bloating messages.
- **A general prover** can prove/verify any actor's execution
  ([zkPVM](zkpvm.md)), and the `clerk` actors already work with
  commitments + nullifier-style redemption keys — the same family of
  primitives a zk-object needs (commitment + serial number + valid-
  transition proof).
- **Identity and per-agent ACLs** exist at the platform layer
  ([Identity](identity.md), [Authorization](authorization.md)) — the hook
  where signed membership and credentials plug in.

What is *not* yet built: the MLS encryption layer, the per-message
authorization circuit, the bulletin-board ordering service, and any
metadata-protecting transport. Those are the work, and the honest open
problems below are why.

## Open problems

These are stated plainly because they decide how private "private" really
is.

1. **The bulletin board wants a consistent global view — which fights
   leaderlessness.** zk-promises needs replay/fork prevention
   (nullifiers) and *non-membership* proofs for callbacks ("this penalty
   is not yet applied"). Both require an agreed-upon current root — an
   ordering/consensus property, the opposite of the merkle-CRDT's
   "converge in any order." Eventual consistency makes "has this callback
   settled?" racy. The likely resolution is a **per-channel ordering
   checkpoint** (a small rotating quorum or an accumulator checkpointed
   periodically) that publishes the board root, while bulk message
   replication stays gossip/CRDT.
2. **Metadata privacy is not provided by the lower layers.** Encryption
   hides content; zk-promises hides *which* member acted; neither hides
   gossip timing, which channels you fetch, or the social graph. True
   metadata privacy needs mixing / cover traffic / private retrieval —
   the hardest and least-mature layer, and where "most private" is
   actually won or lost.
3. **Client-state compromise has a horizon.** Backward anonymity holds
   only back to callback expiry; a seized or compromised device reveals
   its unexpired callbacks, hence its recent posts. The zk-promises
   authors flag this themselves — it bounds the protocol's use for the
   most sensitive applications.
4. **Proof cost on the hot path.** A SNARK per message is viable only
   with a fast proof system over a fixed circuit (the zk-promises bench:
   client < 1 s, verify < 4 ms with Groth16). The VOS STARK/PVM prover is
   the wrong tool for per-message latency — reserve it for rare,
   high-stakes governance actions and use a fixed circuit (and
   session-scoped, not per-keystroke, proofs) for routine posting.

See [Security Analysis & Open Questions](security-analysis.md) for the
full treatment.

## Installing messaging into a space

Messaging is shipped as ordinary VOS actors, so it installs like any other
agent set — no special build:

```bash
# A channel is a crdt-mode agent backed by merkle-crdt.
vosx space call demo chat post --in '{"text":"hello"}'
vosx space agents demo
```

Concretely, a channel maps onto VOS as:

| Channel concept | VOS mechanism |
|---|---|
| Channel | A `crdt`-mode agent (one `MerkleCrdt` instance) |
| Message | A DAG node carrying an (encrypted) CRDT op |
| Membership | An OR-Set CRDT in the space's root document |
| Moderation log | An append-only CRDT = the zk-promises bulletin board |
| Posting right | A zk-promises proof attached to the node |

## Further reading

- [Sync Layer: Merkle-CRDTs](sync.md) — the DAG and anti-entropy
- [Encryption Layer](encryption.md) — MLS group key management
- [Anonymous Moderation: zk-promises](zk-promises.md) — the governance layer
- [Privacy Analysis by Layer](privacy-layers.md) · [Threat Model](threat-model.md) · [Security Analysis](security-analysis.md)
- [Merkle-CRDTs paper](https://arxiv.org/abs/2004.00107) · [zk-promises paper](https://eprint.iacr.org/2024/1260)
