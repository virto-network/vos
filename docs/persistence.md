# Persistence

Kunekt peers need a way to persist encrypted DAG nodes so that data
survives restarts, device loss, and periods when all peers are offline.
Because every piece of stored data is encrypted and content-addressed,
the storage layer can be remarkably simple: backends are untrusted
blob stores that never see plaintext. This chapter covers how
content addressing works, what backends are available, how they
compose, and the hard economic questions that come with storing data
in a decentralized system.

## Content addressing

Every DAG node is identified by its content hash (CID). The CID is
computed deterministically from the node's serialized bytes — same
input always yields the same CID, regardless of who computes it or
where.

This gives us three properties that the entire storage layer depends on:

- **Deduplication** — if two peers independently produce the same DAG
  node (e.g. identical edits merged to the same state), the CID is
  identical. Only one copy needs to be stored.
- **Integrity verification** — any peer that fetches a blob can
  recompute the CID from its contents and confirm the data has not
  been tampered with. A relay that corrupts or substitutes data is
  detected immediately.
- **Location independence** — a CID says *what* the data is, not
  *where* it lives. The same CID can be fetched from a local database,
  a Nostr relay, an IPFS node, or a blockchain DA layer. The consumer
  does not need to know the source — only that the hash matches.

### Hash function commitment

Kunekt's CID scheme commits to a specific hash function (encoded in
the CID's multicodec prefix, following the CID specification). Changing
the hash function — for instance moving from BLAKE3 to a
post-quantum hash — constitutes a migration. All existing CIDs become
references to the old scheme and must be re-hashed under the new one.
This is a coordinated, space-wide operation. The practical implication
is that the hash function choice is a long-lived commitment and should
be made conservatively.

## Storage tiers

A peer may use multiple storage backends simultaneously. Each tier
offers different tradeoffs in latency, durability, cost, and trust
assumptions.

### Local storage

The peer's own database — SQLite for resource-constrained devices,
sled for embedded use cases, or a plain filesystem for maximum
portability. This is the primary working copy: always available,
lowest latency, and the only tier that is fully trusted.

Local data is encrypted at rest. The encryption key is derived from
the peer's root secret (see [encryption](encryption.md) for key
derivation details). Even if the device's disk is imaged, an attacker
without the root secret sees only ciphertext.

The local schema is minimal:

| Column        | Description                                      |
|---------------|--------------------------------------------------|
| `cid`         | Content identifier (primary key)                 |
| `blob`        | Encrypted DAG node bytes                         |
| `document_id` | Which document this node belongs to              |
| `epoch`       | MLS epoch during which this node was created     |
| `stored_at`   | Timestamp of local insertion                     |

The `document_id` and `epoch` columns are metadata that support
garbage collection and epoch-based key rotation. They are not part
of the CID computation — they are local bookkeeping.

### Relay storage

Nostr relays serve as dumb blob stores. Kunekt pushes encrypted DAG
nodes as Nostr events, tagged with their CID. Peers pull nodes by
querying for events matching a CID tag. See nostr for
the event format and relay interaction protocol.

Relays are untrusted. They see encrypted blobs and CID tags — nothing
more. A relay operator cannot read, modify, or selectively censor
content without detection (modification is caught by CID verification;
censorship is mitigated by using multiple relays).

For redundancy, spaces can be configured to push to multiple relays.
If one relay goes offline or purges data, the others still hold copies.
Relay storage is the default remote tier: it is cheap, widely
available (the Nostr relay ecosystem already exists), and requires
no blockchain fees.

### Distributed storage

A DHT (distributed hash table) or IPFS network where content-addressed
data is spread across many participating nodes. Content addressing
maps naturally to these systems — the CID *is* the lookup key.

Distributed storage provides better redundancy than a single relay
at the cost of higher and less predictable latency. It is most useful
for data that needs to survive the loss of all relays — a fallback
tier rather than a primary one.

### Blockchain DA layer

A data availability (DA) layer on a blockchain provides the strongest
durability guarantee. Data is replicated across validators and is
available as long as the chain operates. This tier offers:

- **Censorship resistance** — validators cannot selectively suppress
  blobs without consensus-level misbehavior.
- **Guaranteed availability** — economic incentives (staking, slashing)
  ensure validators serve data or face penalties.
- **Auditability** — the fact that data *was* published at a given
  block height is publicly verifiable.

The DA layer only stores encrypted blobs — validators cannot read the
content. This tier is expensive relative to relays and is appropriate
for high-value or high-risk spaces: legal records, financial
coordination, whistleblower communication.

### Tiered policy

Each space configures a **storage policy** that specifies which tiers
to use and the desired replication factor within each tier. Examples:

- **Casual chat**: local + 2 relays. Cheap, good enough availability.
- **Team workspace**: local + 3 relays + DHT. Higher redundancy,
  tolerates relay churn.
- **High-security archive**: local + relay + DA layer. Maximum
  durability, censorship resistance. Higher cost.

The policy is set by the space administrator and can be updated over
time. When a new tier is added, existing nodes are backfilled
asynchronously. When a tier is removed, its data is left in place
(there is no way to force a remote backend to delete) but is no
longer actively replicated.

## Storage backend trait

All storage backends implement a single trait:

```rust
trait Store<H: Hasher, P: Payload> {
    type Error;
    fn get(&self, cid: &Cid<H>) -> Result<Option<DagNode<H, P>>, Self::Error>;
    fn put(&mut self, cid: Cid<H>, node: DagNode<H, P>) -> Result<(), Self::Error>;
    fn contains(&self, cid: &Cid<H>) -> Result<bool, Self::Error>;
}
```

Three methods. That's it. The interface is deliberately minimal — any
system that can store and retrieve bytes by key can implement it. This
is what makes the tiered architecture possible: the sync engine does
not know or care whether it is talking to a SQLite database, a Nostr
relay, or a blockchain node.

### Why this is sufficient

Content addressing eliminates the need for complex query interfaces.
There are no range queries, no secondary indexes, no joins. A peer
knows which CIDs it needs (from the DAG structure and sync state)
and asks for them by name. `contains` is an optimization — it lets
a peer skip fetching data it already has.

Updates are never in-place. A DAG node, once written, is immutable.
There is no `update` or `delete` in the trait. This makes
replication trivial: `put` is idempotent and commutative across
backends.

### Implementations

- **`MemStore`** — in-memory hash map. Used for tests and ephemeral
  sessions.
- **`SqliteStore`** — SQLite database on disk. The default local
  backend for desktop and server peers.
- **`SledStore`** — embedded sled database. Suitable for
  resource-constrained environments.
- **`NostrRelayStore`** — wraps a Nostr relay connection. `put`
  publishes a Nostr event; `get` queries by CID tag.
- **`DhtStore`** — wraps a DHT client. `put` announces the value;
  `get` performs a DHT lookup.
- **`DaStore`** — wraps a blockchain DA layer client. `put` submits
  a blob transaction; `get` queries by blob commitment.

### Multi-backend adapter

A `MultiStore` adapter composes multiple backends into one. Writes
fan out to all configured backends. Reads try backends in priority
order (typically: local first, then relay, then DHT, then DA layer)
and return the first successful result.

```
MultiStore [
  SqliteStore (local, priority 0),
  NostrRelayStore (relay-a.example, priority 1),
  NostrRelayStore (relay-b.example, priority 1),
  DaStore (priority 2),
]
```

This is the primary interface the sync engine uses. It does not need
to know how many backends exist or which one responded — it gets a
`DagNode` or an error.

## Garbage collection and pruning

### The growth problem

Every edit to a document creates at least one new DAG node. In an
active space with frequent edits — a team chat room, a collaborative
document — DAG nodes accumulate fast. A space with 50 active members
producing 100 messages per day generates roughly 3,000 nodes per
month, each carrying an encrypted payload plus structural overhead.
Over a year, that is 36,000 nodes. Heavy collaboration spaces will
generate far more.

Without pruning, storage grows without bound. This is a problem for
local storage (disk budget) and for relay storage (operator goodwill
or payment).

### Local garbage collection

The sync protocol supports **snapshot compaction** (see
[sync](sync.md)): periodically, a peer computes a snapshot that
represents the full materialized state at a point in time. Once a
snapshot exists and is confirmed stored on remote backends, all DAG
nodes that the snapshot supersedes can be deleted locally.

The rule: keep at least the most recent snapshot plus all nodes
created after it. Everything older is prunable.

Peers should be conservative about pruning. A node that has been
pruned locally must be re-fetched from a remote backend if needed
again. Aggressive pruning saves disk space but increases network
traffic.

### Remote garbage collection

Kunekt cannot force remote backends to delete data. A Nostr relay
may keep events indefinitely; a DA layer certainly will. But this
is acceptable because **all remote data is encrypted**. Without the
decryption keys, stored blobs are indistinguishable from random bytes.

After an MLS epoch rotation, the keys for the old epoch are ratcheted
forward and (ideally) deleted. Data encrypted under old-epoch keys
is effectively dead to anyone who did not hold the keys at the time.
Even if a relay stores old blobs forever, they are cryptographically
inaccessible to future attackers.

This is not true garbage collection — the bytes still exist on disk
somewhere — but it achieves the security property that matters:
old data cannot be read.

### TTL-based expiry

Some Nostr relays enforce a TTL (time-to-live) on events. If Kunekt
relies on such a relay, it must periodically re-publish important
data — snapshots, recent DAG nodes, pending sync heads — before the
TTL expires. The `MultiStore` adapter can handle this automatically
by tracking publication timestamps and re-publishing when a
configurable TTL threshold approaches.

This is a tradeoff: TTL relays are cheaper to operate (they bound
storage) but require active maintenance from peers. A peer that goes
offline for longer than the TTL risks losing remote copies. The
mitigation is to use at least one non-TTL backend (a second relay,
a DA layer) alongside TTL relays.

### Quota management

Local storage can be configured with a per-space budget (e.g. 500 MB
per space). When the budget is exceeded, the oldest prunable nodes are
evicted first — nodes that are older than the most recent snapshot and
that are confirmed replicated to at least one remote backend.

If no nodes are prunable (everything is newer than the last snapshot),
the peer triggers a snapshot compaction to create a pruning
opportunity. If the space is still over budget after compaction, the
peer alerts the user — the budget may need to be increased or the
space's edit rate is simply too high for the configured storage.

## Data availability and redundancy

### Erasure coding

For spaces that require strong durability without fully trusting any
single backend, Kunekt can split encrypted blobs into fragments using
Reed-Solomon erasure coding. A blob is encoded into *n* fragments
such that any *k* of them are sufficient to reconstruct the original
(where *k < n*). The fragments are distributed across different
backends.

This means no single backend holds enough data to be a single point
of failure, and no single backend holds enough data to be useful to
an attacker (even if the encryption were somehow broken, each
fragment is incomplete). Erasure coding is an optional feature — it
adds complexity and is only warranted for high-value spaces.

### Replication factor

The replication factor is configurable per space and defaults to 3
(i.e. each node is stored on at least 3 backends). The `MultiStore`
adapter tracks which backends have acknowledged a `put` and considers
a write durable only when the replication target is met. If a write
fails to meet the target (e.g. one relay is temporarily down), it is
retried in the background.

### Availability monitoring

Peers periodically probe their configured backends to verify that
data is still available. The simplest probe is a `contains` check
on a random sample of CIDs. If a backend consistently fails probes,
the peer marks it as degraded and increases replication to the
remaining backends.

In later phases (see roadmap), Kunekt may support
cryptographic proof-of-storage via zero-knowledge challenges: a peer
challenges a backend to prove it holds a specific blob without
transferring the entire blob. This is a Phase 4 feature — the
protocol design is not yet finalized.

### Repair

If a backend goes offline permanently (a relay shuts down, a DHT node
leaves), the replication factor drops below the target. The peer
detects this through availability monitoring and triggers a **repair**
operation: missing data is read from a surviving backend and written
to a replacement backend, restoring the replication factor.

Repair is cooperative — any peer in the space that holds the data can
perform it. This distributes the bandwidth cost across the group
rather than placing it on a single peer.

## Sync and storage interaction

### Fetch path

When a peer needs a DAG node it does not have locally, it walks the
backend priority list:

1. **Local store** — check the local database. If found, return
   immediately.
2. **Relay store** — query configured Nostr relays by CID tag. If
   found, verify the CID, store locally, and return.
3. **DHT store** — perform a DHT lookup. Higher latency, but reaches
   a wider network.
4. **DA layer store** — query the blockchain. Slowest and potentially
   costly (RPC fees), but data is guaranteed to be there if it was
   ever published.

The peer stops at the first tier that returns the data. Every fetched
blob is verified by recomputing the CID before use — a corrupted or
substituted blob is rejected regardless of source.

### Store path

When a peer creates a new DAG node (a new message, a document edit):

1. The node is encrypted under the current MLS epoch key.
2. The CID is computed from the encrypted blob.
3. The node is stored locally.
4. The node is pushed to all configured remote backends according to
   the space's storage policy.
5. The replication factor is tracked. If any backend fails, the push
   is retried asynchronously.

### Caching

Frequently accessed remote nodes are cached locally. The cache is
bounded by the space's local storage quota and uses LRU eviction.
Cached nodes are not counted toward the replication factor — they are
ephemeral local copies that may be evicted at any time.

Caching is particularly important for spaces where a peer has pruned
old nodes locally but still needs to access them occasionally (e.g.
scrolling back through chat history).

## Storage privacy

Even though all stored data is encrypted, the *pattern* of storage
operations can leak information. This section outlines the threats
and mitigations. See [privacy-layers](messaging.md#security) for a
comprehensive analysis.

### Read privacy

Which CIDs a peer requests from a relay reveals what content it is
interested in. A relay operator — or a network observer — can build
an interest profile by logging queries.

Mitigations:

- **Private information retrieval (PIR)**: cryptographic protocols
  that let a peer query a relay without revealing which CID it wants.
  Computationally expensive; practical only for small query volumes.
- **Bulk download**: fetch all events for a space rather than
  individual CIDs. Hides which specific nodes are of interest but
  increases bandwidth.
- **Multi-relay split**: distribute queries across multiple relays so
  that no single relay sees the full query pattern.

### Write privacy

When a peer stores data reveals when it is active. A relay operator
can infer online hours, timezone, and activity patterns.

Mitigations:

- **Batched writes**: accumulate nodes locally and push to relays in
  periodic batches rather than immediately after each edit. Adds
  latency but hides fine-grained timing.
- **Cover traffic**: inject dummy (encrypted, indistinguishable) writes
  at random intervals to mask real activity. Wastes bandwidth and
  relay storage but disrupts timing analysis.

### Access pattern hiding

If a peer's device may be physically compromised (seized, stolen with
root secret intact), the local storage access pattern itself is a
threat. An adversary with disk access could analyze which blocks were
recently accessed.

The strongest defense is **Oblivious RAM (ORAM)**, which hides access
patterns by shuffling data on every read/write. ORAM is expensive — it
multiplies I/O cost by a logarithmic factor. It is a defense against
a specific, powerful adversary (someone with ongoing disk access and
the decryption key) and is not enabled by default.

## Economics

Storage costs real resources — disk space, bandwidth, electricity —
and someone has to pay for them. This is one of the biggest open
questions for real-world deployment of any decentralized storage
system, and Kunekt is no exception.

### Who pays?

Each storage tier has different cost bearers:

- **Local storage**: the peer pays, via their own device's disk. This
  is free in the economic sense (the user already owns the device) but
  limited in capacity.
- **Relay storage**: the relay operator pays for disk and bandwidth.
  Today's Nostr relay ecosystem runs largely on goodwill and donations.
  This works for low-volume usage but does not scale to heavy
  commercial workloads.
- **DHT storage**: DHT participants collectively bear the cost. Like
  relay operators, they are currently volunteers. The sustainability
  question is the same.
- **DA layer storage**: the blockchain's fee market determines the
  cost. This is the only tier with a clear, built-in economic model —
  users pay transaction fees and validators are compensated through
  block rewards and fees. It is also the most expensive tier by a
  wide margin.

### Incentive models

Kunekt aims to be **incentive-model agnostic**. The protocol does not
mandate a specific payment mechanism but provides hooks for different
models:

- **Free tier (community relays)**: relay operators donate resources,
  as in the current Nostr ecosystem. Sustainable for small-scale,
  community-driven spaces. No guarantees — the relay may disappear
  without notice.
- **Paid storage**: space members pay relay operators for guaranteed
  storage and bandwidth. Payment could be via cryptocurrency
  micropayments (Lightning, stablecoin transfers) or traditional
  billing. The relay commits to a service level (retention period,
  availability uptime) in exchange for payment.
- **Cooperative model**: space members contribute storage to each
  other. Each member runs a small relay (or a relay-like daemon) and
  stores other members' data. This distributes cost and eliminates
  the need for external relay operators. It works well for small,
  trusted groups but requires that some members are online at any
  given time.
- **DA layer fees**: determined by the blockchain's fee market. No
  Kunekt-specific design needed — the peer simply pays the gas cost
  for blob submission.

### Cost estimation

Rough order-of-magnitude numbers for a moderately active space (50
members, 100 messages/day, average message payload 1 KB after
encryption):

| Tier           | Monthly cost estimate          | Notes                          |
|----------------|--------------------------------|--------------------------------|
| Local          | ~0 (uses device disk)          | ~100 MB/year                   |
| 3 Nostr relays | ~0 (free relays) to ~$1-5/mo   | Paid relays charge per-event   |
| DHT            | ~0 (volunteer network)         | No SLA                         |
| DA layer       | ~$10-100+/mo                   | Highly variable by chain       |

These numbers will shift as the ecosystem matures. The point is that
relay-based storage is cheap enough for most use cases, and DA layer
storage is reserved for situations where the durability guarantee
justifies the cost.

### Open questions

- **How does a relay prove it is actually storing data?** Without
  proof-of-storage, a paid relay could accept payment and silently
  discard blobs. ZK proof-of-storage (Phase 4 on the
  roadmap) addresses this, but the mechanism is not
  yet designed.
- **How are relay payments coordinated among space members?** Does one
  member pay, or is the cost split? Kunekt's group key management
  (MLS) could potentially be extended to coordinate payment splits,
  but this is unexplored.
- **What happens when a free relay disappears?** The redundancy
  strategy (multiple relays, replication factor) mitigates this, but
  users need clear UX signals about their data's durability status.
- **Can storage incentives be built into the protocol itself?** A
  token-based incentive layer is a common answer in the decentralized
  storage space (Filecoin, Arweave), but adding a token introduces
  regulatory complexity and misaligned incentives. Kunekt's current
  position is to avoid a protocol-native token and instead support
  pluggable payment mechanisms.

The honest answer is that sustainable decentralized storage economics
are an unsolved problem industry-wide. Kunekt's design minimizes the
surface area of this problem — encrypted, content-addressed blobs are
the simplest possible unit of storage, compatible with any backend
and any payment model — but it does not solve the economic question
itself. That is left to the deployment context and the communities
that run the infrastructure.
