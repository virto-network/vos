# Replication: Local, Raft, and CRDT

A VOS v2 consistency mode belongs to one installed root actor tree. The root
and every owned child execute inside one generic JAM service and therefore
share its scheduler, atomic Accumulate transaction, and replication boundary.
Calls to another root tree always cross the durable outbox/inbox protocol.

| Mode | Replication | Admission rule | Best fit |
|---|---|---|---|
| `ephemeral` | none | exact current revision | disposable state and tests |
| `local` | durable local image | exact current revision and state root | one-node applications |
| `raft` | replicated request log | leader orders the exact Accumulate request | ledgers and uniqueness |
| `crdt` | causal Merkle DAG | every declared causal dependency is available | conflict-free collaboration |

Local and Raft transitions are linear. Refine binds the current revision and
state root; guest Accumulate rejects a stale result intact so the scheduler can
run it again from a fresh base. Raft replicates canonical
`AccumulateRequestV2` bytes and every replica applies them through physical
IC-5. It does not replicate an `EffectLog` or a leader-produced state image.

CRDT is explicit source-level opt-in with `#[actor(crdt)]`. Ordinary actors may
use Ephemeral, Local, or Raft without CRDT field overhead, and installation
rejects an ordinary actor configured as CRDT. A CRDT actor uses the replicated
field types under `vos::crdt`:

- `Value<T>` retains concurrent assignments and exposes them through
  `conflicts()`, while every replica selects the same visible value;
- `Map<K, V>` is an observed-remove map with an independent value register per
  key;
- `Set<T>` is an add-wins observed-remove set;
- `List<T>` is an RGA-style sequence with stable element IDs;
- `Text` applies the same sequence model to Unicode scalar edits;
- `Counter` preserves every additive positive or negative operation.

One execution slice emits one canonical CRDT change containing stable operation
IDs and causal metadata. It never uses wall-clock timestamps. Concurrent DAG
branches are retained; deterministic winner selection is local to a declared
`Value` or duplicate workflow step and never discards a whole branch.

The Merkle DAG supplies causal transport, content addressing, ancestry checks,
and persistence. It does not make arbitrary payloads converge. Application
state must still use a convergent type, which is why plain mutable fields are
rejected in `#[actor(crdt)]` definitions.

Workflow state has its own built-in CRDT operations for ingress, continuations,
replies, outbox records, timeouts, spawns, and upgrades. A resumed VM continues
against the causal snapshot captured at its await boundary; later concurrent
state is merged with the operations it emits, not injected into its suspended
heap. Identical replicas of one workflow step deduplicate by stable invocation
and call IDs. Divergent results for that same step are invalid transitions.

Continuation bytes are content addressed before their headers become visible.
Local commits flush pages before the service image, Raft makes the exact request
durable through its log/application cursor, and CRDT nodes are activated only
after their complete ancestry and referenced blobs are present and verified.

Choose Raft, or design a purpose-built conflict-free construction, for rules
that require global uniqueness, overdraft prevention, irreversible ordering,
or a single authoritative winner. The CRDT mode provides causal convergence,
not global finality.

Implementation details and wire contracts are in [runtime-v2.md](runtime-v2.md).
The lower-level DAG protocol is described in [Sync Layer:
Merkle-CRDTs](sync.md).
