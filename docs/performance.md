# Performance & Scalability

This chapter provides concrete performance analysis for Kunekt's
protocol stack. Every number is either measured, estimated from known
properties of the underlying primitives, or clearly marked as
uncertain. The goal is to give implementers a realistic understanding
of where the performance boundaries are, what can be optimized, and
what is fundamentally constrained.

For the protocol layers referenced here, see
[Architecture Overview](./architecture.md). For security properties
and their costs, see [Security Analysis](threat-model.md).

---

## 1. Performance Budget

A single collaborative operation — one user types a character, that
edit reaches a remote peer and is applied — passes through every layer
of the stack. The following table breaks down the latency contribution
of each stage for a typical real-time editing session using 100ms
operation batching.

```
Stage                                    Latency (estimate)
─────────────────────────────────────────────────────────────
CRDT operation generation (Automerge)    < 1 ms
Merkle-DAG node creation + CID          < 1 ms
  (Blake3 hash of serialized node)
MLS epoch key encryption (AES-128-GCM)  1–5 ms
Serialization + padding to bucket size  < 1 ms
Batching delay (configurable)           100 ms (default)
─────────────────────────────────────────────────────────────
Transport (direct WebSocket)            < 50 ms
Transport (Tor, 3-hop circuit)          200–500 ms
Transport (Nym mixnet)                  1–5 s
─────────────────────────────────────────────────────────────
Remote: deserialize + decrypt + apply   1–5 ms
─────────────────────────────────────────────────────────────
Total end-to-end (direct)               ~150–160 ms
Total end-to-end (Tor)                  ~300–600 ms
Total end-to-end (Nym)                  ~1.1–5.1 s
```

**Key observations:**

- The protocol stack itself (CRDT + DAG + encryption + serialization)
  adds roughly 5ms. The dominant cost is always the transport layer.
- The batching delay is tunable. Reducing it to 50ms halves the
  local wait at the cost of doubling the number of DAG nodes (and
  therefore encryption operations, relay writes, and storage).
- Over Tor, the system is comfortably usable for collaborative
  editing. Users experience latency comparable to typing in a shared
  Google Doc over a slow connection.
- Over Nym, real-time keystroke-level collaboration is impractical.
  Nym is suited for asynchronous messaging (chat, comments, file
  sharing) where multi-second latency is acceptable.

### Anonymous mode overhead

When Phase 3 anonymous mode is active, proof generation adds to the
latency — but only at session start, not per operation:

```
Session-start proof (ShowAuthorized):
  Native Rust (Groth16):    300–900 ms
  WASM (browser):           1.5–3.5 s
  Mobile (ARM):             1–3 s

Per-operation (session token validation):  < 1 ms
```

The session token amortizes the proof cost over the session's
lifetime. See [Security Analysis](threat-model.md), section 2
for the anonymity tradeoff this introduces.

---

## 2. Sync Scalability

### Group size

MLS uses a ratchet tree where key operations (Add, Remove, Update,
Commit) require work proportional to the tree height: **O(log n)**
where n is the number of members.

```
Members     Tree height     Commit cost (key derivations)
──────────────────────────────────────────────────────────
10          ~4              ~4
100         ~7              ~7
1,000       ~10             ~10
10,000      ~14             ~14
```

The Commit message size also grows with tree height (each path node
carries an encrypted key update), but the growth is logarithmic. For
a group of 10,000 members, a Commit message is roughly 14 path nodes
* ~200 bytes = ~2.8KB — well within the Nostr event size limit.

**Practical limit:** MLS group operations are viable up to roughly
10,000 members. Beyond that, the cost is not the tree operations
themselves but the Welcome message for new joiners (which contains the
full ratchet tree state) and the increased likelihood of concurrent
Commits causing epoch conflicts that require resolution.

### Document size

Automerge handles documents up to approximately 100MB in practice.
Beyond that, memory consumption during merge operations becomes
problematic on client devices. For Kunekt's typical use cases:

- Chat history: grows linearly, effectively unbounded (messages are
  append-only, individual messages are small).
- Collaborative documents: practical limit around 10-50MB of
  Automerge state, depending on edit history complexity.
- Configuration and metadata documents: negligible size (< 100KB).

### DAG growth rate

The number of DAG nodes produced depends on the batching interval and
the number of active editors:

```
Batching     Editors     Nodes/hour     Nodes/day (8h active)
──────────────────────────────────────────────────────────────
100 ms       1           36,000         288,000
100 ms       5           up to 180,000  up to 1,440,000
500 ms       1           7,200          57,600
500 ms       5           up to 36,000   up to 288,000
1 s          1           3,600          28,800
```

"Up to" because concurrent editors may produce separate nodes within
the same batch window. In practice, with reasonable batching and
typical editing patterns (pauses between bursts), the actual rate is
significantly lower than the theoretical maximum.

### Anti-entropy cost

The sync protocol exchanges root CIDs and then walks the DAG
difference. The cost is proportional to the **divergence** between
peers, not the total history size.

- **Short disconnection** (minutes): a few hundred nodes to exchange.
  Sync completes in seconds even over Tor.
- **Long disconnection** (days): potentially thousands of nodes.
  Still manageable — the data transfer is the bottleneck, not the
  comparison algorithm.
- **Cold sync** (new joiner): the peer must fetch the entire DAG.
  For a space with 1 million nodes at ~500 bytes each, that is ~500MB.
  At Tor speeds (~200KB/s sustained), this takes roughly 40 minutes.

**Mitigation for cold sync:** DAG snapshot compaction (see Section 7).
A compacted snapshot reduces the cold sync payload to the current
document state plus a truncated recent history.

---

## 3. Storage Costs

### Per-node overhead

Each Merkle-DAG node stored on a Nostr relay consists of:

```
Component                        Size (bytes)
──────────────────────────────────────────────
CID (Blake3-256 hash)            36 (multihash format)
Children CIDs (1-2 parents)      36–72
Encrypted payload (padded)       variable, bucketed
MLS epoch reference              32
Padding to bucket size           variable
Nostr event envelope             ~200 (JSON framing, signature, tags)
──────────────────────────────────────────────
Typical total per node           300–1,000 bytes
```

### Space storage estimates

```
Space type                Monthly data    With 3x replication
───────────────────────────────────────────────────────────────
Quiet chat (10 msgs/day)   ~15 KB/month    ~45 KB/month
Active chat (100 msgs/day) ~1.5 MB/month   ~4.5 MB/month
High-volume chat (1K/day)  ~15 MB/month    ~45 MB/month
Light document editing     ~5 MB/month     ~15 MB/month
Heavy document editing     ~50 MB/month    ~150 MB/month
Config/metadata docs       < 100 KB/month  < 300 KB/month
```

These estimates assume average node sizes of ~500 bytes (chat) and
~800 bytes (document edits with Automerge operation payloads).

### Relay economics

Nostr relay storage is generally free today. Most relays accept events
without payment. This is unlikely to hold at scale — a single active
Kunekt space producing 50MB/month of encrypted, opaque events provides
no value to the relay operator (they cannot index or display it).

Expected evolution:
- Free relays will impose size or rate limits.
- Paid relays (NIP-42 authenticated, or satoshi-per-event pricing)
  will become the norm for heavy use.
- Self-hosted relays remain an option for communities willing to run
  infrastructure.

Storage costs should be budgeted at approximately the cost of
equivalent cloud object storage ($0.02-0.05/GB/month) as a
conservative baseline.

---

## 4. ZK Proof Performance

Zero-knowledge proofs are the most computationally expensive
operations in the protocol. They are also the most platform-sensitive
— performance varies dramatically between native code and WASM.

### Proof generation times

```
Proof type                  Native (Rust)   WASM (browser)   Mobile (ARM)
──────────────────────────────────────────────────────────────────────────
ShowAuthorized (Groth16)    300–900 ms      2–5 s            1–3 s
  (membership + reputation
   + rate limit + ban check)

Callback processing         200–500 ms      1–3 s            0.5–2 s
  (update zk-object state)

BBS+ selective disclosure   50–100 ms       200–500 ms       100–300 ms
  (cross-space credential)

Merkle membership proof     200–400 ms      1–2 s            0.5–1.5 s
  (tree depth 20)
```

### Proof verification times

Verification is fast on all platforms — this is a key property of
Groth16.

```
Proof type                  Verification time
──────────────────────────────────────────────
Groth16 (any circuit)       5–10 ms
BBS+ disclosure             10–20 ms
Merkle membership           5–10 ms
```

### Circuit sizes (estimated constraint counts)

```
Circuit                          Constraints (approx.)
──────────────────────────────────────────────────────
ShowAuthorized                   ~50,000–100,000
  Pedersen commitment opening    ~5,000
  Merkle path verification (d=20) ~20,000
  Range proof (reputation ≥ T)   ~10,000
  Nullifier derivation           ~5,000
  Rate limit check               ~10,000

Callback processing              ~30,000–60,000
  Previous state opening         ~5,000
  State transition               ~10,000
  New state commitment           ~5,000
  Merkle update proof            ~10,000
```

These are rough estimates. Actual constraint counts depend on the
hash function used inside the circuit (Poseidon is ~250 constraints
per hash vs. SHA-256 at ~25,000), the field arithmetic, and the
specific Arkworks gadgets employed.

### Client hardware requirements

- **Desktop/laptop (modern):** All proofs are practical. ShowAuthorized
  at session start is imperceptible to the user (sub-second).
- **Modern smartphone (2022+):** Session-start proofs are tolerable
  (1-3s). Per-operation proofs are not — they would add seconds of
  latency to every action.
- **Older smartphone / low-end devices:** Session-start proofs may
  take 5-10s. The SDK should show a progress indicator. Delegating
  proof generation to a trusted companion device is an option but
  weakens the trust model.
- **WASM (browser):** 2-5x slower than native due to runtime overhead
  and limited access to SIMD instructions. Acceptable for session-start
  proofs; too slow for per-operation proofs.

---

## 5. Bandwidth

### Per-operation bandwidth

Operations are padded to fixed bucket sizes to prevent payload size
from leaking information about content (see
[Privacy Analysis](threat-model.md)). The smallest bucket is 1KB.

```
Component                           Size
─────────────────────────────────────────────
Padded encrypted payload            1 KB (minimum bucket)
Nostr event envelope                ~200 bytes
Total per operation (outbound)      ~1.2 KB
```

For an active editor producing one batch per 100ms, outbound bandwidth
is roughly **12 KB/s** (43 MB/hour). In practice, batches are only
produced when the user is actively editing, so sustained bandwidth is
much lower.

### Cover traffic

Cover traffic sends dummy messages at a constant rate to prevent
traffic analysis from distinguishing active periods from idle periods.

```
Cover traffic rate     Bandwidth overhead
───────────────────────────────────────────
1 msg / 10 s           ~7 KB/min, ~420 KB/hour
1 msg / 5 s            ~14 KB/min, ~840 KB/hour
1 msg / 2 s            ~36 KB/min, ~2.1 MB/hour
1 msg / 1 s            ~72 KB/min, ~4.3 MB/hour
```

The default configuration targets 1 dummy message per 5 seconds as a
balance between anonymity and bandwidth. Users on constrained
connections can reduce the rate at the cost of weaker traffic analysis
resistance.

### Tor circuit overhead

Tor adds per-cell overhead across 3 hops:

- Cell size: 514 bytes (512 payload + 2 header).
- A 1KB application payload spans 2 cells.
- Each cell is encrypted 3 times (once per hop), but the on-wire
  size does not grow — each hop decrypts one layer.
- Circuit establishment: ~3-5 round trips, ~1-2s. Amortized across
  all operations on the circuit.

### MLS key management bandwidth

```
Message type              Size             Frequency
──────────────────────────────────────────────────────────
MLS Commit               1–10 KB          Per key rotation
  (varies with tree size)
MLS Welcome (new member)  5–50 KB          Per member addition
  (contains ratchet tree)
MLS Proposal             ~200–500 bytes    Per membership change
Root CID announcement    64–128 bytes      Per sync round
```

Key rotation frequency is configurable. More frequent rotation
provides better forward secrecy but increases bandwidth. A rotation
every 100 operations or every 10 minutes (whichever comes first) is a
reasonable default.

---

## 6. Scalability Limits

### Where does the system break?

The following analysis identifies the practical ceiling for each
dimension of scale and what constrains it.

**Group size:**
MLS tree operations scale O(log n) and are practical to ~10,000
members. The binding constraint is not computational cost but Welcome
message size for new joiners (~50KB for a 10,000-member tree) and the
probability of concurrent Commits. At 10,000 members with frequent
key rotation, epoch conflicts become common enough to degrade
performance. Mitigation: reduce key rotation frequency for large
groups, or partition into sub-groups with a federation layer.

**Concurrent editors:**
CRDT merge is correct at any scale — convergence is guaranteed
regardless of the number of concurrent editors. The constraint is
network bandwidth: each active editor produces ~12KB/s of outbound
data, and each peer must receive and process all of it. For N active
editors, each peer handles ~12N KB/s of inbound data.

```
Active editors    Inbound bandwidth per peer
──────────────────────────────────────────────
5                 ~60 KB/s
20                ~240 KB/s
50                ~600 KB/s
100               ~1.2 MB/s
```

At 50+ concurrent active editors over Tor, bandwidth becomes
strained. At 100+, the system is likely to experience noticeable lag
as peers fall behind on processing. Practical limit for real-time
editing: ~20-50 concurrent editors. For asynchronous collaboration
(not all editing simultaneously), there is no meaningful limit.

**Storage scalability:**
Content-addressed storage scales horizontally. Adding more Nostr
relays (or other backends) increases both capacity and redundancy.
The constraint is not storage capacity but retrieval — a peer must
know which relays hold the nodes it needs. Relay discovery and
selection is a protocol-level problem, not a storage-level one.

**ZK proving:**
Proof generation is CPU-bound and single-threaded (Groth16 does not
parallelize well). A client can generate roughly 1-3 ShowAuthorized
proofs per second on modern hardware. This is sufficient for
session-start proofs but would be a bottleneck if per-operation proofs
were required. Future proof systems (Jolt, SP1) may relax this
constraint.

### Bottleneck analysis

For most deployments, the system will hit limits in this order:

1. **Transport latency** (Tor/Nym) — the largest single contributor
   to user-perceived delay. Irreducible without relaxing anonymity.
2. **Concurrent editor bandwidth** — scales linearly with active
   editors. Mitigated by batching and compression.
3. **Cold sync time** — grows with total DAG history. Mitigated by
   snapshot compaction.
4. **ZK proving on low-end devices** — limits adoption of anonymous
   mode on constrained hardware. Mitigated by session tokens and
   future proving improvements.
5. **MLS group size** — logarithmic scaling is forgiving, but very
   large groups (>10K) encounter operational friction.

---

## 7. Optimization Strategies

### Operation batching

Batching amortizes the per-operation overhead of encryption, DAG node
creation, and relay transmission. Instead of one DAG node per
keystroke, multiple CRDT operations are bundled into a single node.

- **Default batch interval:** 100ms. Imperceptible to users, reduces
  node creation rate by 10-100x compared to per-keystroke granularity.
- **Adaptive batching:** Increase the interval during high-frequency
  editing bursts; decrease during pauses. This smooths bandwidth
  without increasing perceived latency.

### Lazy sync

Peers should not sync documents they are not actively viewing.

- On space open: sync only the space's metadata and unread message
  indicators.
- On document open: sync the full document DAG.
- On document close: stop syncing, retain the local state for offline
  access.

This dramatically reduces bandwidth for users who are members of many
spaces but actively use only a few at a time.

### Compression before encryption

CRDT operations (especially Automerge) contain redundant structure.
Compressing the batch payload before encryption reduces the data that
must be padded and transmitted.

- Expected compression ratio for Automerge operations: 2-4x (they
  contain repeated field names and structural overhead).
- Compression must happen before encryption — encrypted data is
  incompressible.
- Use a fast compressor (zstd or lz4) to avoid adding latency.

### DAG snapshot compaction

For long-lived spaces, the DAG can grow to millions of nodes. Cold
sync (fetching the entire DAG) becomes impractical.

Snapshot compaction produces a single DAG node containing the current
Automerge document state, with all prior history pruned. The snapshot
node becomes the new root, and old nodes can be garbage collected
from relays.

- **Tradeoff:** Compaction destroys per-operation history. Users can
  no longer inspect individual edits from before the snapshot.
- **Frequency:** Compact when DAG size exceeds a threshold (e.g.,
  100,000 nodes or 50MB).
- **MLS interaction:** The snapshot must be encrypted with the current
  epoch key. Members who were present before the snapshot but left
  before it was created cannot access the compacted state (forward
  secrecy is preserved).

### Connection pooling

Tor circuit establishment takes 1-2 seconds. Reusing circuits across
multiple operations avoids this cost.

- Maintain a pool of 2-3 established Tor circuits.
- Route operations for different spaces through different circuits
  (to avoid linking spaces at the relay level).
- Rotate circuits periodically (every 10 minutes) to limit the
  window for traffic analysis.

### Incremental proving (future)

Nova recursive proofs allow a new proof to "fold in" the previous
proof rather than re-proving the full statement from scratch. Applied
to zk-promises:

- The first ShowAuthorized proof is full cost (~700ms).
- Subsequent proofs (after a state change like a reputation update)
  fold the delta into the previous proof: estimated ~50-200ms.
- This could make per-batch proofs practical, eliminating the need
  for session tokens and improving per-operation anonymity.

This is speculative — Nova integration with Arkworks is not yet
mature, and the interaction with the zk-promises circuit structure
has not been validated.

### Client-side caching

Peers should cache DAG nodes locally to avoid redundant relay fetches.

- Cache keyed by CID (content-addressed, so cache entries never go
  stale).
- LRU eviction with a configurable cache size (default: 100MB).
- On sync: check the local cache before fetching from a relay. For
  spaces with multiple relays, this avoids fetching the same node
  from each relay during replication checks.

---

## 8. Benchmarking Plan

The following measurements must be collected before production release,
across the target platforms (native Linux/macOS/Windows, WASM in
modern browsers, Android, iOS).

### End-to-end latency

Measure the time from CRDT operation creation on Peer A to operation
application on Peer B.

```
Scenario                              Target          Platforms
──────────────────────────────────────────────────────────────────
Single edit, direct transport         < 200 ms        All
Single edit, Tor transport            < 700 ms        All
Batch (100ms window), direct          < 250 ms        All
Batch (100ms window), Tor             < 750 ms        All
Session start (with ZK proof), Tor    < 2 s           Native
Session start (with ZK proof), Tor    < 5 s           WASM
```

### Sync performance

```
Scenario                              Target          Notes
──────────────────────────────────────────────────────────────────
Incremental sync (100 new nodes)      < 5 s (Tor)     After short disconnect
Incremental sync (10,000 nodes)       < 60 s (Tor)    After long disconnect
Cold sync (100,000 nodes)             < 10 min (Tor)  New joiner, no snapshot
Cold sync (snapshot)                  < 30 s (Tor)    New joiner, with snapshot
```

### ZK proof generation

```
Circuit                    Native target   WASM target    Mobile target
──────────────────────────────────────────────────────────────────────────
ShowAuthorized             < 1 s           < 5 s          < 3 s
Callback processing        < 500 ms        < 3 s          < 2 s
BBS+ selective disclosure  < 100 ms        < 500 ms       < 300 ms
Merkle membership          < 400 ms        < 2 s          < 1.5 s
```

### Bandwidth usage

Measure per-user bandwidth (inbound + outbound) for defined activity
profiles:

```
Profile                     Target (Tor)        Measurement period
──────────────────────────────────────────────────────────────────────
Idle (cover traffic only)   < 1 MB/hour         1 hour
Light chat (10 msgs/hour)   < 2 MB/hour         1 hour
Active chat (100 msgs/hour) < 10 MB/hour        1 hour
Active editing (1 editor)   < 50 MB/hour        1 hour
Active editing (10 editors) < 150 MB/hour       1 hour
```

### Storage growth

Track per-space storage on relay and on local device:

```
Profile                     Relay storage/month   Local cache/month
──────────────────────────────────────────────────────────────────────
Quiet chat space            < 100 KB              < 100 KB
Active chat space           < 5 MB                < 5 MB
Active document space       < 100 MB              < 100 MB
```

### What to do with the results

Benchmarks that exceed targets should be investigated for:

1. **Algorithmic inefficiency** — can the operation be done with fewer
   steps?
2. **Unnecessary serialization/deserialization** — are we copying data
   that could be passed by reference?
3. **Suboptimal batching** — are we creating more DAG nodes than
   necessary?
4. **Transport overhead** — are we making more round trips than
   necessary?
5. **Platform-specific issues** — is WASM performance limited by a
   specific operation (e.g., big-integer arithmetic)?

Results should be published as part of the protocol specification so
that independent implementations can validate their performance
against the reference.

---

## Summary

Kunekt's performance profile is dominated by the transport layer.
The protocol stack itself — CRDTs, Merkle-DAGs, MLS encryption — adds
single-digit milliseconds per operation. The anonymity layer (Tor or
Nym) adds hundreds of milliseconds to seconds. ZK proofs are expensive
but amortized over sessions.

The system is practical for real-time collaboration over Tor with up
to ~20-50 concurrent editors. Over Nym, it is suited for asynchronous
communication. Group sizes up to ~10,000 members are feasible with
MLS's logarithmic scaling. Storage scales horizontally through
content-addressed replication across multiple backends.

The primary optimization levers are batching (reduce per-operation
overhead), lazy sync (reduce unnecessary bandwidth), snapshot
compaction (reduce cold sync time), and connection pooling (reduce
Tor circuit setup cost). Longer-term, advances in ZK proving
(incremental proofs, faster proof systems) could eliminate the
session-token compromise and enable true per-operation anonymity.
