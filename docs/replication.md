# Replication: CRDT vs Raft

> Scaffold — to be expanded.

Each `[[agent]]` in a manifest picks one of four consistency modes.
The choice is local to the agent: a single space can mix all four.

| Mode | Replication | Read-from-any-replica | Writes block on |
|---|---|---|---|
| `ephemeral` | none, in-memory | n/a | nothing |
| `local` | redb on local disk | n/a | local fsync |
| `crdt` | merkle-CRDT, eventual | yes | local commit |
| `raft` | Raft consensus, strict | leader only (today) | quorum ack |

**CRDT** fits commutative state — counters, sets, LWW maps,
append-only logs — where reads-from-anywhere are valuable and
divergence is naturally healed by the merge function.

**Raft** fits strictly sequenced state — ledgers, unique-name
registries, anything where two concurrent writes must be ordered
rather than merged.

## What this chapter will cover

- Picking a mode: the decision tree
- The Merkle-CRDT layer: DAG nodes, anti-entropy, the `merkle-crdt` crate
- Raft cluster setup, membership, and leader-only reads (today)
- How the registry threads consistency-mode metadata into the runtime
- The `crdt` consistency mode also underpins VOS's sync layer — see
  [Sync Layer: Merkle-CRDTs](sync.md) for the protocol-level treatment

## Source map

- [`merkle-crdt/`](https://github.com/virto-network/vos/tree/master/merkle-crdt)
- [`vos-raft/`](https://github.com/virto-network/vos/tree/master/vos-raft)
- [`vos/src/raft/`](https://github.com/virto-network/vos/tree/master/vos/src/raft)
- [`vos/src/data_layer.rs`](https://github.com/virto-network/vos/tree/master/vos/src/data_layer.rs)
