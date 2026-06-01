# Table: persistent typed map for actor state

> Design note. Not part of the book TOC. Status: **proposed**, 2026-05-11.

## Why

Actor state today lives entirely in memory, reconstructed by replaying
the CRDT DAG or Raft log on cold start. This breaks for any table
that grows without bound:

- **OOM** at scale. A bank with 10M accounts × ~200B per archived
  `Account` = 2GB+ resident per replica. Real cipher-clerk
  deployments expect 10s-100s of millions of notes, transfers,
  audit records.
- **Slow cold start.** Replay every historical event before the
  agent can serve traffic. Linear in lifetime ops, not in live set
  size.
- **Wasted RAM.** Almost every read hits a tiny hot subset
  (recently-active accounts, current settlement window). The rest
  sits in memory paying for the privilege.

clerk-ledger is the immediate driver. The federation demo fits in
memory (thousands of accounts per bank); a real bank deployment
doesn't. Other vos consumers with the same shape:

- cipher-clerk's L2 note pool — unbounded append-only commitments +
  nullifier set
- transfer history — unbounded log of all kernel transfers
- audit-export rows, FMD flag history, settlement claim archives
- any user-facing application built on vos: chat history, document
  metadata, social-graph edges

## What

A `Table<K, V>` type that looks like a `BTreeMap` to actor code but
reads / writes through the host into redb. The actor's rkyv archive
holds only a handle; the contents live on disk.

```rust
#[actor]
pub struct ClerkLedger {
    journal_id: Option<[u8; 16]>,
    registrar_pubkey: Option<[u8; 32]>,
    #[vos(table = "accounts")]
    accounts: Table<AccountId, Account>,
}

#[messages]
impl ClerkLedger {
    #[msg]
    async fn create_account(&mut self, ...) -> u8 {
        // ... validation ...
        self.accounts.insert(acct.id, acct).await;
        STATUS_OK
    }

    #[msg]
    async fn account(&self, id: AccountId) -> Option<Account> {
        self.accounts.get(&id).await
    }
}
```

The actor's archived bytes are now `journal_id` + `registrar_pubkey`
+ a small table handle, regardless of how many accounts are in the
table. Replication wire shape is bounded.

## How — host-mediated I/O

Actors are no_std + PVM-resident; redb is std-only. So `Table` can't
be a direct redb wrapper — it's host-mediated, the same shape as
`ctx.fetch` / `ctx.ask` / the existing JAM-style storage hostcalls:

```
actor:  table.get(&key).await
   │
   ├── host_call(EFFECT_TABLE_GET, table_id, key_bytes)
   │
host:  redb_table.get(key_bytes)? → value_bytes
   │
   └── provide_result(value_bytes)
actor:  rkyv decode → Some(value)
```

Actor side is a thin handle + small async wrapper methods. All real
I/O is on the host, where redb already lives (vos persists CRDT
commits / Raft logs in redb today; Table is the same backend
exposed at a typed level).

### Wire-level effect opcodes

Five new `EFFECT_TABLE_*` opcodes, all single-record except
`COUNT`:

| Opcode | Args | Returns | Notes |
|---|---|---|---|
| `EFFECT_TABLE_GET` | `table_id, key_bytes` | `Option<value_bytes>` | |
| `EFFECT_TABLE_INSERT` | `table_id, key_bytes, value_bytes` | `Option<prev_value_bytes>` | |
| `EFFECT_TABLE_REMOVE` | `table_id, key_bytes` | `Option<value_bytes>` | |
| `EFFECT_TABLE_CONTAINS` | `table_id, key_bytes` | `bool` | |
| `EFFECT_TABLE_LEN` | `table_id` | `u64` | |

Range / iteration / transactions deliberately deferred — see
"Phasing" below.

## How — replication semantics

The hard part. Different consistency modes need different stories:

### `Consistency::Local` mode (trivial)

Single-node only. Table writes hit redb directly. No replication, no
gossip, no events. Simplest mode; ship first.

### `Consistency::Raft` mode (tractable)

Each table write proposes a Raft entry:

```rust
enum RaftEntry {
    // ... existing variants ...
    TableInsert { table: TableId, key: Vec<u8>, value: Vec<u8> },
    TableRemove { table: TableId, key: Vec<u8> },
}
```

The leader proposes, followers apply in total order. Each follower
keeps its own redb; replay produces byte-identical state. Reads on
the leader are immediate (apply-then-respond); reads on followers
serve the locally-applied snapshot.

This is the *useful* mode for cipher-clerk and most strict-consistency
consumers. **Ship this with Local.**

### `Consistency::Crdt` mode (open problem)

Per-key LWW is the simplest correct answer:

```rust
struct CrdtEvent {
    // ... existing fields ...
    op: CrdtOp,
}

enum CrdtOp {
    // existing variants...
    TableInsert {
        table: TableId,
        key: Vec<u8>,
        value: Vec<u8>,
        origin: NodeId,
        seq: u64,
    },
    TableRemove { table: TableId, key: Vec<u8>, origin: NodeId, seq: u64 },
}
```

Conflict resolution: highest `(seq, origin)` wins per key. Tombstones
needed for delete-then-insert ordering. Eventually consistent across
the DAG.

**But:** snapshot consistency disappears. There's no "table state at
time T" in a CRDT under partition. Iteration becomes "iterate the
keys this replica has seen so far, which may differ from another
replica's view." For use cases that need linearizable iteration
(audit exports, settlement reconciliation), CRDT-mode Table is
**not the right answer** — use Raft mode or expose iteration as a
separate refine-phase primitive.

Recommendation: ship Local + Raft modes first. Leave CRDT-mode Table
as "open problem, may not be the right shape" until a real CRDT
consumer asks.

### `Consistency::Ephemeral` mode

Tables are inherently persistent. Setting `consistency = ephemeral`
on a table is a configuration error — reject at agent registration
time.

## How — typed serialization

Keys and values go through rkyv on the actor side. The host stores
opaque bytes; type safety is the actor's responsibility.

```rust
impl<K, V> Table<K, V>
where
    K: rkyv::Archive + rkyv::Serialize<...>,
    V: rkyv::Archive + rkyv::Serialize<...> + rkyv::Deserialize<...>,
{
    pub async fn get(&self, key: &K) -> Option<V> {
        let key_bytes = rkyv::to_bytes(key)?;
        let value_bytes = ctx.host_call(EFFECT_TABLE_GET, ...).await?;
        rkyv::from_bytes(&value_bytes).ok()
    }
    // ...
}
```

Key encoding decision: keys MUST encode lexicographically so range
queries (Phase 2) match the key's logical ordering. Rkyv archives
of fixed-size primitives (u64, [u8; N]) are byte-lexicographic for
unsigned little-endian. For mixed-byte-shape keys, callers either
use fixed-size keys or accept that range queries reflect rkyv byte
order, not logical order.

(redb itself stores raw bytes and orders by `Ord` on `&[u8]`, so
the constraint is real: pick keys whose byte representation aligns
with their logical ordering.)

## Hard parts

### 1. Transactions across operations

`apply_batch` is atomic: a four-entry transfer either lands all four
account updates or none. With Table, that's "read 4, write 4" —
needs a transaction boundary.

redb has transactions. Exposing them across the host boundary is the
hard part — naïve `with_transaction(|t| { ... })` requires
closure-over-async + a handle that's only valid inside the closure.

Proposed v2 shape:

```rust
let mut txn = self.accounts.transaction().await;
let from = txn.get(&from_id).await?;
let to = txn.get(&to_id).await?;
// ... mutate ...
txn.insert(from_id, from).await;
txn.insert(to_id, to).await;
txn.commit().await?;
```

The actor holds a transaction handle (just a u32 token); the host
maintains the redb transaction state until commit / rollback /
drop. Commit failure: collision with a concurrent transaction in
the host. Rare in single-actor case (no other transaction interferes
with this actor's redb); contention happens across actors sharing
state via cross-actor calls.

**Deferred until first real consumer needs it.** clerk-ledger's
initial transfer handler can do the read-modify-write in actor
memory and write each account in sequence — for the federation
demo with small batches this is fine.

### 2. Iteration / range queries

Pulling a full range into actor memory defeats the purpose for big
tables. Cursor handles work but add wire-protocol surface:

```rust
let mut cur = self.accounts.range(from..to).await;
while let Some((k, v)) = cur.next().await {
    // ...
}
```

Host tracks cursor state (current position in the redb range scan)
keyed by a u32 cursor id. Actor drops the cursor (or calls explicit
`close`) when done.

**Deferred until first real consumer needs it.** L2 notes pool's
`prove_inclusion_at(anchor_version)` needs range scans; settlement
reconciliation's "claims in window [t1, t2]" too. Plan for it, don't
ship it in v1.

### 3. Cold-start time

Even with Table, an actor still has to replay any *non-Table* state
on cold start (the journal_id + registrar_pubkey for clerk-ledger
are trivial; bigger non-Table state in other actors might not be).

Tables themselves are O(1) cold start — the redb is already on disk
from the last run, the actor just attaches the handle.

This shifts the cold-start question: **identify which actor state
should be in Tables vs in the actor struct**. Hot, small, often-mutated
state stays in the struct. Cold, large, append-mostly state goes in
Tables.

### 4. Snapshot consistency vs replication mode

Refine-phase reads need a stable snapshot (per cipher-clerk's
`apply_batch_refine` contract). redb has MVCC — refine reads can
see a snapshot taken at refine-entry time, regardless of writes
landing concurrently.

In Raft mode this composes cleanly: the snapshot is "state at
log-index N", same as the Raft worker uses for log truncation.

In CRDT mode it doesn't — there's no globally-consistent snapshot
under partition. The refine contract effectively requires Raft mode
when Tables are involved.

## Alternatives considered

### (a) Use vos's existing `READ` / `WRITE` storage hostcalls

vos likely already exposes JAM-style storage hostcalls (per the
refine-mode flag in `runtime.rs`). If so, `Table<K, V>` is a
~100-LOC typed wrapper over those hostcalls — no new framework
primitive. **Probably the right starting point.** Check what's
there before building anything new.

The risk: the existing storage hostcalls may be flat-namespace
(one key-space per service) where Table wants per-table namespaces.
That's solvable by prefixing keys with the table id, but it leaks
the table-id concept into the storage hostcalls' wire format.

### (b) Make the table a separate actor

An `accounts-table` actor that holds `Vec<Account>` internally;
other actors `ctx.ask` it. **Defeats the whole point** — the
table-actor still holds full state in memory; every access is now
an actor-to-actor invoke (slower); transactions across keys
require a custom RPC; replication of the table-actor is itself
the unsolved problem at a different layer.

### (c) Memory cache layer over redb

Hot keys stay resident, cold keys fault in. Better latency profile
than pure-redb but adds eviction policy, cache invalidation across
replicas, and a memory-vs-redb consistency window. Eventual answer
maybe, premature now.

### (d) JAM service storage primitive

JAM has a service-storage model with refine-mode read-only access +
accumulate-mode write-back. If vos already implements this for
service-mode actors, `Table` is the typed sugar over that storage.
**Most aligned with where vos is heading** if JAM is the long-term
target.

## Phasing

| Phase | Scope | Drivers |
|---|---|---|
| **1** | `Table<K, V>` typed wrapper over existing storage hostcalls. Local mode only. `get` / `insert` / `remove` / `contains` / `len`. No transactions, no iteration. | Whichever actor first hits the memory wall |
| **2** | Raft-mode replication. Each table op is a `RaftEntry` variant; followers apply in order. | clerk-ledger at real bank scale |
| **3** | Transaction handles. `txn.get` / `txn.insert` / `txn.commit`. Required for atomic multi-account operations. | cipher-clerk's `apply_batch` if it's not feasible to keep batches in-memory |
| **4** | Range cursors. `table.range(from..to).await.next().await`. | L2 notes inclusion proofs, settlement window queries |
| **5** | (Open) CRDT-mode semantics. Per-key LWW probably; OR-Map maybe. May be the wrong shape for tables — could end up as a separate "CrdtTable" type or stay deferred indefinitely. | None today |

Phase 1 + 2 cover 80% of cipher-clerk's needs. Phase 3 is required for
the kernel's atomicity contract. Phase 4 unlocks the L2 pool's
real-world use. Phase 5 may never ship.

## Why we're NOT building this for the federation demo

The whole demo fits in memory (3 banks × maybe 100 accounts × 200B
= 60KB). Premature abstraction has a real cost: shipping Table v1
with wire-stable opcodes that we'll regret in v2 is worse than
shipping clerk-ledger with `BTreeMap<AccountId, Account>` and
swapping to Table later.

Better path:
1. Ship clerk-ledger + the bank federation on `BTreeMap` state.
2. When cipher-clerk's L2 notes pool lands (first unbounded
   consumer), check whether existing storage hostcalls are enough
   (alternative (a)).
3. If yes: ship the typed wrapper, no new framework primitive.
4. If no: design Table proper from the L2-pool requirements (real,
   measurable, not projected).

## Open questions

1. **Are vos's existing storage hostcalls sufficient?** Need a
   10-minute probe of `runtime.rs::handle_ecall` for `READ` /
   `WRITE` / equivalents. If yes, Table is library code; if no, it's
   a framework primitive.

2. **Does redb's per-table overhead matter at vos scale?** Each
   actor might want 5-20 logical tables. redb supports multiple
   named tables in one database file; per-table overhead is small.
   Probably fine.

3. **Wire-format migration story.** Once Table v1 ships and real
   data is in redb, schema migrations (e.g. adding a field to a
   value type) need either rkyv-version-tolerant decode or an
   explicit migration pass. Open.

4. **Cross-actor table sharing.** Two actors that want to read
   from the same table (e.g. clerk-disclosure reading clerk-ledger's
   accounts table) — does that go through `ctx.ask` to the owning
   actor, or directly through redb? Direct-redb breaks the actor
   isolation model. `ctx.ask` is correct but slow. Open.

5. **Refine-phase Tables.** cipher-clerk's `apply_batch_refine`
   wants a read-only snapshot. Map this to redb's MVCC read txn.
   Open.

## Recommendation

Land this doc. Don't build Table for clerk-ledger v1. Use `BTreeMap`
for now (sorted Vec was the wrong choice — picky review #16 from
the Phase 3 review). When cipher-clerk's L2 notes pool actor needs
to land, revisit with concrete requirements and build Phase 1 from
there.
