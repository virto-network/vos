# merkle-crdt

One sync scope's operations as a Merkle-DAG of signed nodes, applied
incrementally to a storage-backed CRDT. `no_std`; the fjall store is behind
the default `fjall` feature.

Based on H. Sanjuán, S. Pöyhtäri, P. Teixeira, I. Psaras, *"Merkle-CRDTs:
Merkle-DAGs meet CRDTs"*, 2020 ([arXiv:2004.00107](https://arxiv.org/abs/2004.00107)).
VOS uses it for the Merge lane and the light node's sealed scopes (its
design docs `docs/design/core-model.md` §9.4 and `docs/design/light-node.md`
§3.6, which land with the light node).

## The model

- **A node** (`Node<H, O>` = `DagNode<H, Signed<O>>`) is content-addressed:
  its CID is the hash of its canonical bytes, and it names its parents by
  theirs, at most `MAX_PARENTS` (64). The payload carries the author's
  ed25519 key, the author's sequence number, a signature over the scope,
  the operations and the parents, and the operations.
- **Authors' chains:** an author numbers its nodes from 0; each later node
  names the author's previous one among its parents. A node that does not is
  refused, with its descendants. Two nodes at one number are an
  equivocation: both applied, reported once, and listed for the CRDT's reads
  to filter.
- **A replica** (`Replica`) keeps in memory the heads, each author's latest
  number, the equivocations, the cursor, the outbox, the held nodes'
  missing parents and the latest refused CIDs (at most 4096). `ingest`
  checks each node statelessly (`validate`: canonical bytes, CID, at most
  `MAX_PARENTS` parents, strict signature), then applies only the new
  nodes, in causal order, onto the current rows, holding (durably) those
  whose parents have not arrived. `record` applies a local operation in
  place. Each is one atomic `Store` commit: nodes, index, heads, cursor,
  outbox and the CRDT's rows together.
- **The CRDT** (`Apply`) reads and writes rows through `Rows` only, so its
  state commits with the nodes it came from. Its result must not depend on
  the order of concurrent nodes, nor on which of two equivocating nodes is
  told it equivocates (the one that arrives second). A row key is 1 to
  65,535 bytes: a write past that fails the batch (`Error::Row`) in every
  store.
- **Fetching** is the caller's, sans I/O: it hands nodes' bytes to
  `ingest` in any order and batching, with the feed position they were read
  to; `Replica::wanted`, `Replica::have` and `Replica::cursor` say what to
  fetch next.

## Who may write

Every ed25519 key is an author: the library admits any node whose signature
checks. A caller whose scope has a set of writers checks each node's author
before `ingest` (`validate`, then `Header::read`). The bounds below hold for
any author; they are what keeps a writer that is admitted and hostile from
costing a replica without limit.

## Bounds

- **Parents.** A node names at most `MAX_PARENTS`; one naming more does not
  decode. `record` names the author's previous node, then heads of authors
  that never equivocated, then the other heads, up to the bound. The heads it
  leaves stay heads, and later local nodes may name them, up to
  `MAX_PARENTS - 1` a node. So an author that signs thousands of forks makes the heads many but
  no local node large.
- **Forks and convergence.** Whether a node is applied depends only on its
  bytes and its ancestors (signature, chain, parents applied), never on
  whether a later node names it. Every replica that is delivered the same
  nodes (and delivered again any it dropped at a held bound) applies the
  same set and so has the same heads, rows and equivocations, whichever
  heads its own nodes named. A head no node names converges like any
  other, as long as every node reaches every replica by delivery (a feed of
  all of them): a fetch that follows only the heads, or each author's
  highest number (`have`), misses a fork no node names. What naming changes is causal order: a local node
  is after the heads it names and concurrent with the rest, and a CRDT must
  accept either. Forks come last, so a local node names the other honest
  authors' latest nodes before an equivocating author's, and a CRDT that
  orders by parents (a Lamport clock) puts it after them.
- **Held nodes.** At most `MAX_HELD` (4096) in all, `MAX_HELD_PER_AUTHOR`
  (256) of one author, and `MAX_HELD_BYTES` (32 MiB). A node past a bound is
  dropped (`Ingested::dropped`): not refused, so delivered again once its
  parents are applied it applies; a cursor given with the batch passes it.
  `drop_held` drops one author's held nodes, or all. `open` reads held
  nodes one at a time, for their headers.
- **Refused nodes** are remembered in memory only, the latest 4096: a node
  naming one is refused at once, a node naming one forgotten or refused
  before a restart is held, within the bounds above.
- **Local operations** whose node does not decode (an `Encode` past what
  `Decode` takes, such as a vector past 1,000,000 items) are refused by
  `record` (`Error::Unencodable`) before anything is written.

## Limits

- Nothing is pruned: applied nodes, the author index, each author's latest
  number, the equivocations and the CRDT's rows grow with the history, and
  in memory so do the heads (with forks, or new authors) and the
  equivocations. A
  caller bounds what its writers may send.
- A compromised author key can filter that author's whole past: a second
  node at its number 0 is an equivocation at 0.
- A store error leaves it unknown whether the batch was written until the
  store is opened again (fjall may have written its journal): a caller
  reopens before it retries an operation.
- One replica a store.

## Stores

The layout is not versioned: a store written by an earlier layout of this
crate (one row of all heads, before heads were a row each) does not open,
and is made again from its peers.

| Store | |
|---|---|
| `MemStore` | in memory: tests, benchmarks |
| `FjallStore` | one scope in keyspaces `<name>.*` of a fjall database the caller opens and may share; its rows in `<name>.rows` or a keyspace the caller names; each commit one synced batch |

After a crash the caller mends the fjall database before it opens it: a
database whose creation was cut short is cleared, and the journals are
synced, so a batch the killed process left in the page cache is durable
before the replica relies on it (on VOS, `vos_exec::store::recover`).

## Tests

`cargo test -p merkle-crdt`: the incremental replica against a full replay
of its nodes over random DAGs, deliveries, duplicates and batchings
(property tests), equivocations, refusals, a cursor read out of causal
order, the parent and held-node bounds, failed commits and reads, and the
fjall store reopened and killed mid-write.

## Cost

`cargo bench -p merkle-crdt --bench apply` measures applying one node, a
batch of 100 and a local operation onto 1k, 100k and 1M operations; the
results are recorded in `docs/design/core-model.md` §9.4.
