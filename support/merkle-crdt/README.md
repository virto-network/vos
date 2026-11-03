# merkle-crdt

One sync scope's operations as a Merkle-DAG of signed nodes, applied
incrementally to a storage-backed CRDT. `no_std`; the fjall store is behind
the default `fjall` feature.

Based on H. Sanjuán, S. Pöyhtäri, P. Teixeira, I. Psaras, *"Merkle-CRDTs:
Merkle-DAGs meet CRDTs"*, 2020 ([arXiv:2004.00107](https://arxiv.org/abs/2004.00107)).
VOS uses it for the Merge lane (`docs/design/core-model.md` §9.4) and the
light node's sealed scopes (`docs/design/light-node.md` §3.6).

## The model

- **A node** (`Node<H, O>` = `DagNode<H, Signed<O>>`) is content-addressed:
  its CID is the hash of its canonical bytes, and it names its parents by
  theirs. The payload carries the author's ed25519 key, the author's
  sequence number, a signature over the operations and the parents, and the
  operations.
- **Authors' chains:** an author numbers its nodes from 0; each later node
  names the author's previous one among its parents. A node that does not is
  refused, with its descendants. Two nodes at one number are an
  equivocation: both applied, reported once, and listed for the CRDT's reads
  to filter.
- **A replica** (`Replica`) keeps in memory only the heads, each author's
  latest number, the equivocations, the cursor, the outbox and the held
  nodes' missing parents. `ingest` checks each node statelessly (`validate`:
  canonical bytes, CID, strict signature), then applies only the new nodes,
  in causal order, onto the current rows, holding (durably) those whose
  parents have not arrived. `record` applies a local operation in place.
  Each is one atomic `Store` commit: nodes, index, heads, cursor, outbox and
  the CRDT's rows together.
- **The CRDT** (`Apply`) reads and writes rows through `Rows` only, so its
  state commits with the nodes it came from. Its result must not depend on
  the order of concurrent nodes. `rebuild` replays a whole DAG from nothing,
  for recovery and audits.
- **Fetching** (`sync`), in batches, sans I/O: `Replica::wanted` and
  `Replica::have` say what to ask a peer that walks the DAG (`serve` answers
  up to a byte budget), and `Replica::cursor` where to read a feed that only
  numbers what it accepted (`since(position)`); `ingest` takes what came
  back. `Replica::sync` and `Replica::catch_up` drive both over blocking
  `Source` and `Feed` implementations.

## Stores

| Store | |
|---|---|
| `MemStore` | in memory: tests, benchmarks |
| `FjallStore` | one scope in keyspaces `<name>.*` of a fjall database the caller opens and may share; its rows in `<name>.rows` or a keyspace the caller names; each commit one synced batch |

## Cost

`cargo bench -p merkle-crdt --bench apply` measures applying one node, a
batch of 100 and a local operation onto 1k, 100k and 1M operations; the
results are recorded in `docs/design/core-model.md` §9.4.
