//! Commit strategies — how an actor's state is persisted and (later)
//! replicated.
//!
//! The host picks a strategy per actor at deploy time based on the
//! service manifest. Today only [`NoCommit`] and [`LocalCommit`]
//! exist; `CrdtCommit` (merkle-crdt replication) and `RaftCommit`
//! (strong consistency) are planned follow-ups.
//!
//! A strategy owns its own backend (redb database, network handle,
//! etc.) and any change-detection bookkeeping. The host calls
//! [`CommitStrategy::restore`] once at startup and
//! [`CommitStrategy::commit`] after every dispatch.

// `Path` is only referenced by the storage-backed strategies' `open`.
#[cfg(feature = "storage")]
use std::path::Path;

/// Error type for commit operations.
///
/// `Config` covers misuse of the API (e.g., `Crdt` consistency
/// requested without a `data_dir`). `Backend` wraps any underlying
/// I/O error (typically redb) so `?` can be used without a
/// stringification dance at every call site.
#[derive(Debug)]
pub enum CommitError {
    /// Configuration error — caller supplied incompatible options.
    Config(String),
    /// Backend I/O failure. The inner error is preserved for the
    /// caller to inspect via [`std::error::Error::source`].
    Backend(Box<dyn std::error::Error + Send + Sync>),
}

impl core::fmt::Display for CommitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Config(s) => write!(f, "configuration error: {s}"),
            Self::Backend(e) => write!(f, "backend error: {e}"),
        }
    }
}

impl std::error::Error for CommitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(_) => None,
            Self::Backend(e) => Some(&**e),
        }
    }
}

#[cfg(feature = "storage")]
mod from_redb {
    use super::CommitError;

    impl From<redb::DatabaseError> for CommitError {
        fn from(e: redb::DatabaseError) -> Self {
            Self::Backend(Box::new(e))
        }
    }
    impl From<redb::TableError> for CommitError {
        fn from(e: redb::TableError) -> Self {
            Self::Backend(Box::new(e))
        }
    }
    impl From<redb::StorageError> for CommitError {
        fn from(e: redb::StorageError) -> Self {
            Self::Backend(Box::new(e))
        }
    }
    impl From<redb::TransactionError> for CommitError {
        fn from(e: redb::TransactionError) -> Self {
            Self::Backend(Box::new(e))
        }
    }
    impl From<redb::CommitError> for CommitError {
        fn from(e: redb::CommitError) -> Self {
            Self::Backend(Box::new(e))
        }
    }
}

/// Persistence/replication strategy for an actor's serialized state.
///
/// Implementations are opaque about what's inside the state bytes —
/// they only see and store them. CRDT-shaped strategies layer
/// additional tables (DAG nodes, roots) on the same backend and
/// override the log-aware methods.
/// Per-replica gate run on every peer-merged DAG node before it is
/// stored ([`CrdtCommit::insert_node`]). Returns `true` to accept, `false`
/// to drop the node. `insert_node` only checks `CID == hash(bytes)`, which
/// stops byte-tampering but not a peer authoring a *valid* node the
/// replica must not trust — e.g. a forged genesis. The space-registry
/// installs one that binds the genesis `set_root` to the advertised
/// space_id, so a member can't grind a low-CID `set_root` node to hijack
/// the registry root on replay (grinding a CID to sort low is cheap;
/// grinding one to derive a *specific* space_id is a preimage attack).
/// `None` (the default for every other replica) accepts all nodes.
///
/// Args: `(cid, node_bytes)` — the node's content-id and its full
/// `DagNode` wire bytes.
pub type NodeValidator = alloc::sync::Arc<dyn Fn(&[u8; 32], &[u8]) -> bool + Send + Sync>;

/// The whole-agent durable unit for one dispatch: everything the
/// dispatch's applied work-results changed, committed in one backend
/// transaction (work-result contract §7).
pub struct AgentDelta<'a> {
    /// Ordered storage mutations from the applied work-results —
    /// `STATE_KEY` included, as just another key; `None` is a delete
    /// tombstone (never on `STATE_KEY` — the wire rejects that). One
    /// ordered list because last-wins per key depends on the
    /// write/delete interleaving. Tasks have no rows of their own, so
    /// this stays small.
    pub writes: &'a [(Vec<u8>, Option<Vec<u8>>)],
    /// `(kind, anchor)` the delta was applied against. NORMATIVE, not
    /// just audit: replay divergence detection compares each replayed
    /// dispatch's re-emitted anchor against the value recorded in the
    /// log node ([`crate::effect_log::EffectLog::anchor`]).
    /// [`crate::effect_log::ANCHOR_UNRECORDED`] when the dispatch
    /// carried no anchor (v2 blobs, old-style actors).
    pub anchor: (u8, [u8; 32]),
    /// EffectLog node: inbound msg + depth-1 invoke replies, anchor
    /// stamped. `None` for commits with nothing to replay (post-replay
    /// materialization, follower apply, extension persistence).
    pub log: Option<&'a crate::effect_log::EffectLog>,
    /// At least one applied v3 work-result carried effects. Drives the
    /// durable-node rule: an effect-bearing dispatch must produce a
    /// durable log node even when the state blob is unchanged (e.g. a
    /// Transfer-only dispatch). `false` for v2 deltas — those guests
    /// emit their full state unconditionally, so "carries effects"
    /// would turn every pure read into a node; value comparison decides
    /// for them instead.
    pub effect_bearing: bool,
}

impl<'a> AgentDelta<'a> {
    /// Delta carrying only a full-state write and no log — the
    /// post-replay materialization / follower-apply / extension shape.
    /// `writes` is the caller-owned single-pair buffer (the borrow has
    /// to outlive the delta).
    pub fn state_only(writes: &'a [(Vec<u8>, Option<Vec<u8>>)]) -> Self {
        Self {
            writes,
            anchor: (crate::effect_log::ANCHOR_UNRECORDED, [0u8; 32]),
            log: None,
            effect_bearing: false,
        }
    }
}

/// What a [`CommitStrategy::commit`] durably produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitReceipt {
    /// Whether a durable log node (DAG node / raft entry) was appended.
    /// `false` for skipped no-ops, state-only materializations, and
    /// non-replicating strategies.
    pub node_appended: bool,
}

pub trait CommitStrategy: Send {
    /// Stable identity to expose to the next handler dispatch, when the
    /// strategy already owns a durable invocation namespace.
    ///
    /// CRDT returns the identity of its next `(replica_origin, seq)` event so
    /// live execution and causal replay derive identical operation IDs.
    /// Strategies whose v2 work envelope is not production-wired yet return
    /// `None`; the host supplies a process-local unique fallback.
    fn pending_invocation_id(&self) -> Option<crate::v2::InvocationId> {
        None
    }

    /// Return previously-persisted state, if any.
    ///
    /// `None` means "fresh start" — the host constructs the actor
    /// via its normal init path. A `None` from a replicating
    /// strategy may also signal "state table empty but DAG present"
    /// — the host should then call [`replay_logs`](Self::replay_logs)
    /// and rebuild state by replaying each entry.
    fn restore(&mut self) -> Option<Vec<u8>>;

    /// Return the non-STATE agent rows persisted by previous deltas,
    /// so the host can rehydrate the runtime's storage alongside
    /// [`restore`](Self::restore). Strategies without a KV backend
    /// return an empty vec.
    fn restore_writes(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, CommitError> {
        Ok(Vec::new())
    }

    /// Durably commit one dispatch's whole-agent delta in a single
    /// backend transaction.
    ///
    /// Skip rules: a delta with no writes and no effect-bearing log is
    /// a pure read — nothing persists, no node appends. A state write
    /// whose bytes equal the last committed state is treated as
    /// unchanged (v2 guests re-emit their full state every dispatch).
    /// An effect-bearing delta appends a durable log node even when
    /// state is unchanged.
    fn commit(&mut self, delta: &AgentDelta<'_>) -> Result<CommitReceipt, CommitError>;

    /// Convenience: commit a bare full-state blob (no log, no effects).
    /// The pre-delta `commit(&[u8])` call shape — post-replay
    /// materialization, follower apply, extension persistence.
    fn commit_state(&mut self, state: &[u8]) -> Result<CommitReceipt, CommitError> {
        let writes = [(
            crate::lifecycle::STATE_KEY_BYTES.to_vec(),
            Some(state.to_vec()),
        )];
        self.commit(&AgentDelta::state_only(&writes))
    }

    /// Durably replace the whole persisted keyspace with the slate a
    /// from-genesis replay rebuilt: `state` plus every non-STATE row.
    ///
    /// A replay recomputes every row from history, so rows earlier
    /// deltas persisted that the replayed execution no longer produces
    /// are stale — a plain delta commit would leave them behind. After
    /// a CRDT merge that's guaranteed to matter: the merged
    /// serialization interleaves remote dispatches, so shared
    /// accumulator rows (index pages, directories) lay out differently
    /// from the local-only history that first persisted them, and the
    /// remote dispatches' own rows were never in this replica's
    /// persisted table at all. Appends no log node: replay materializes
    /// history, it doesn't create any.
    ///
    /// The default forwards to [`commit_state`](Self::commit_state),
    /// which is correct only for strategies without a KV backend
    /// (nothing persisted, so nothing stale). Every strategy whose
    /// [`restore_writes`](Self::restore_writes) returns rows MUST
    /// override this with an atomic state-write + whole-table swap.
    fn commit_rebuilt(
        &mut self,
        state: &[u8],
        rows: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<CommitReceipt, CommitError> {
        let _ = rows;
        self.commit_state(state)
    }

    /// Convenience: commit a full-state blob alongside its effect log.
    /// The pre-delta `commit_with_log` call shape, kept for tests and
    /// simple embedders; the agent thread builds real deltas.
    fn commit_with_log(
        &mut self,
        state: &[u8],
        log: &crate::effect_log::EffectLog,
    ) -> Result<CommitReceipt, CommitError> {
        let writes = [(
            crate::lifecycle::STATE_KEY_BYTES.to_vec(),
            Some(state.to_vec()),
        )];
        self.commit(&AgentDelta {
            writes: &writes,
            anchor: (log.anchor_kind, log.anchor),
            log: Some(log),
            effect_bearing: false,
        })
    }

    /// Return the stored effect logs in causal (topological) order.
    /// Used during crash recovery to rebuild state by re-running the
    /// handler under a replay session for each log.
    ///
    /// Non-replicating strategies return an empty vec.
    fn replay_logs(&self) -> Result<Vec<crate::effect_log::EffectLog>, CommitError> {
        Ok(Vec::new())
    }

    /// Re-read the strategy's in-memory bookkeeping from disk so it
    /// matches whatever has been written to the backing store —
    /// typically because a parallel writer (e.g. the cycle-3 sync
    /// ticker) merged remote DAG nodes while the agent thread was
    /// idle. After this call:
    ///
    /// - [`replay_logs`](Self::replay_logs) reflects the merged DAG.
    /// - The next [`commit`](Self::commit) will skip-on-unchanged
    ///   against the materialized post-merge state, not the pre-
    ///   merge cache.
    ///
    /// Default impl is a no-op for strategies that don't have any
    /// mutable in-memory state (`NoCommit`, `LocalCommit`).
    fn reload(&mut self) -> Result<(), CommitError> {
        Ok(())
    }

    /// Current root CIDs as raw 32-byte arrays — the wire shape
    /// `Frame::Heads` carries. Used by the agent thread after
    /// every commit to publish a head announcement on the
    /// gossipsub topic for this replication group.
    ///
    /// Non-replicating strategies return an empty vec.
    fn roots(&self) -> Vec<[u8; 32]> {
        Vec::new()
    }

    /// Can this strategy currently accept new state-changing
    /// dispatches? `false` means the agent thread should refuse
    /// the invoke before running it (drop the reply channel so
    /// the caller sees a transport-shaped failure) — typical for
    /// a Raft replica that isn't currently the leader. Default:
    /// `true` (every other strategy is always writable).
    fn is_writable(&self) -> bool {
        true
    }

    /// Whether this strategy's durable history is a single totally-
    /// ordered chain (Raft) rather than a mergeable DAG (CRDT). Governs
    /// how replay treats a recorded-anchor mismatch: on a linear
    /// history every replayed dispatch must re-emit exactly the
    /// recorded anchor (a mismatch is real divergence — fail); on a
    /// merged DAG, concurrent branches replay in a serialization their
    /// recorded anchors never saw, so mismatches are expected and only
    /// observable (the reconciliation policy for parallel histories is
    /// an explicit open spike — the anchor guarantees detectability,
    /// not a policy).
    fn linear_history(&self) -> bool {
        false
    }

    /// Whether the agent must run a sync reload (soft-restart) to fold in DAG
    /// nodes the backing store gained out-of-band — the soft-restart's whole
    /// reason to exist (a peer merge by the sync ticker, or a follower applying
    /// the leader's replicated entries).
    ///
    /// The sync notifier fires for *every* committed index, including the echo
    /// of the agent's OWN proposal — the raft relay can't tell the two apart.
    /// Default `true` preserves the historical always-reload behaviour; a
    /// strategy that can recognise a self-commit echo (its committed state
    /// already matches what's on disk) overrides this to return `false` for it,
    /// skipping a soft-restart that would otherwise replay the entire DAG on
    /// every commit (O(n) per commit ⇒ O(n²), which stalls a continuously-
    /// committing actor) and briefly expose genesis while STATE_KEY is deleted
    /// mid-replay.
    fn needs_sync_reload(&self) -> bool {
        true
    }
}

/// No-op strategy — state lives only in memory and is lost on exit.
pub struct NoCommit;

impl CommitStrategy for NoCommit {
    fn restore(&mut self) -> Option<Vec<u8>> {
        None
    }
    fn commit(&mut self, _delta: &AgentDelta<'_>) -> Result<CommitReceipt, CommitError> {
        Ok(CommitReceipt {
            node_appended: false,
        })
    }
}

// ── redb-backed local strategy ──────────────────────────────────────

#[cfg(feature = "storage")]
pub use local::{
    KV_TABLE, LocalCommit, STATE_KEY, STATE_TABLE, read_kv_rows, read_kv_rows_at, split_delta,
    swap_kv_rows,
};

#[cfg(feature = "storage")]
pub use crdt::{Blake2b, CrdtCommit, DAG_TABLE, ROOTS_KEY, read_dag_node, read_roots};

#[cfg(feature = "storage")]
mod local {
    use super::*;

    /// redb table holding the materialized actor state.
    pub const STATE_TABLE: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new("state");

    /// Row key within [`STATE_TABLE`] for the actor's state blob.
    /// Shared with [`crdt::CrdtCommit`] so both strategies write to
    /// the same row when they share a database file.
    pub const STATE_KEY: &str = "actor";

    /// redb table holding the agent's non-STATE storage rows — the rest
    /// of the whole-agent delta ([`AgentDelta::writes`]) beyond the
    /// materialized state blob. Shared by every storage-backed strategy
    /// so the same database file carries the complete agent keyspace.
    pub const KV_TABLE: redb::TableDefinition<&[u8], &[u8]> =
        redb::TableDefinition::new("agent_kv");

    /// Split a delta's ordered mutations into the last `STATE_KEY`
    /// value (last-wins per key) and the non-STATE rows — `None` values
    /// are delete tombstones — preserving order.
    pub fn split_delta<'a>(
        delta: &'a AgentDelta<'_>,
    ) -> (Option<&'a [u8]>, Vec<(&'a [u8], Option<&'a [u8]>)>) {
        let mut state = None;
        let mut rest = Vec::new();
        for (key, value) in delta.writes {
            if key.as_slice() == crate::lifecycle::STATE_KEY_BYTES {
                // A STATE_KEY tombstone can't decode off the wire; if a
                // host-built delta carries one anyway, ignoring it here
                // beats materializing an accidental state wipe.
                if let Some(value) = value {
                    state = Some(value.as_slice());
                }
            } else {
                rest.push((key.as_slice(), value.as_deref()));
            }
        }
        (state, rest)
    }

    /// Read every persisted non-STATE agent row from [`KV_TABLE`].
    /// Backs [`CommitStrategy::restore_writes`] for the storage-backed
    /// strategies.
    pub fn read_kv_rows(db: &redb::Database) -> Result<Vec<(Vec<u8>, Vec<u8>)>, CommitError> {
        use redb::ReadableTable;
        let txn = db.begin_read()?;
        let table = match txn.open_table(KV_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut rows = Vec::new();
        for entry in table.iter()? {
            let (k, v) = entry?;
            rows.push((k.value().to_vec(), v.value().to_vec()));
        }
        Ok(rows)
    }

    /// Open the agent database at `path` and read every persisted
    /// non-STATE row. Diagnostic entry point for comparing replicas'
    /// persisted keyspaces without building a strategy; the database
    /// must not be open elsewhere.
    pub fn read_kv_rows_at(path: &Path) -> Result<Vec<(Vec<u8>, Vec<u8>)>, CommitError> {
        let db = redb::Database::open(path)?;
        read_kv_rows(&db)
    }

    /// Replace [`KV_TABLE`]'s entire contents with `rows` inside `txn`.
    /// Backs [`CommitStrategy::commit_rebuilt`] for the storage-backed
    /// strategies: dropping the table (rather than upserting) is what
    /// clears rows a replay no longer produces.
    pub fn swap_kv_rows(
        txn: &redb::WriteTransaction,
        rows: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(), CommitError> {
        txn.delete_table(KV_TABLE)?;
        let mut kv = txn.open_table(KV_TABLE)?;
        for (key, value) in rows {
            kv.insert(key.as_slice(), value.as_slice())?;
        }
        Ok(())
    }

    /// Persists the agent delta to a redb database, skipping the write
    /// when nothing changed from the last commit.
    pub struct LocalCommit {
        db: redb::Database,
        last: Vec<u8>,
    }

    impl LocalCommit {
        /// Open (or create) the redb database at `path`.
        pub fn open(path: &Path) -> Result<Self, CommitError> {
            let db = redb::Database::create(path)?;
            Ok(Self {
                db,
                last: Vec::new(),
            })
        }

        /// Borrow the underlying redb handle. Used when a higher-
        /// level strategy (e.g. CrdtCommit) needs to share the same
        /// database for its additional tables.
        pub fn db(&self) -> &redb::Database {
            &self.db
        }
    }

    impl CommitStrategy for LocalCommit {
        fn restore(&mut self) -> Option<Vec<u8>> {
            let txn = self.db.begin_read().ok()?;
            let table = txn.open_table(STATE_TABLE).ok()?;
            let bytes = table.get(STATE_KEY).ok().flatten()?.value().to_vec();
            self.last = bytes.clone();
            Some(bytes)
        }

        fn restore_writes(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, CommitError> {
            read_kv_rows(&self.db)
        }

        fn commit(&mut self, delta: &AgentDelta<'_>) -> Result<CommitReceipt, CommitError> {
            let (state, rest) = split_delta(delta);
            let state_changed = state.is_some_and(|s| s != self.last.as_slice());
            if !state_changed && rest.is_empty() {
                return Ok(CommitReceipt {
                    node_appended: false,
                });
            }
            let txn = self.db.begin_write()?;
            {
                if state_changed
                    && let Some(state) = state
                {
                    let mut table = txn.open_table(STATE_TABLE)?;
                    table.insert(STATE_KEY, state)?;
                }
                if !rest.is_empty() {
                    let mut kv = txn.open_table(KV_TABLE)?;
                    for (key, value) in &rest {
                        match value {
                            Some(value) => {
                                kv.insert(*key, *value)?;
                            }
                            None => {
                                kv.remove(*key)?;
                            }
                        }
                    }
                }
            }
            txn.commit()?;
            if let Some(state) = state {
                self.last = state.to_vec();
            }
            Ok(CommitReceipt {
                node_appended: false,
            })
        }

        fn commit_rebuilt(
            &mut self,
            state: &[u8],
            rows: &[(Vec<u8>, Vec<u8>)],
        ) -> Result<CommitReceipt, CommitError> {
            let txn = self.db.begin_write()?;
            {
                let mut table = txn.open_table(STATE_TABLE)?;
                table.insert(STATE_KEY, state)?;
            }
            swap_kv_rows(&txn, rows)?;
            txn.commit()?;
            self.last = state.to_vec();
            Ok(CommitReceipt {
                node_appended: false,
            })
        }
    }
}

// ── CRDT strategy — blake2b-hashed Merkle-DAG on the same redb ──────

#[cfg(feature = "storage")]
mod crdt {
    use super::*;
    use crate::effect_log::{CrdtEvent, EffectLog};
    use alloc::collections::{BTreeMap, BTreeSet};
    use alloc::vec::Vec;
    use merkle_crdt::{Cid, DagNode, Decode as McDecode, Encode as McEncode, Hasher, MerkleClock};
    use std::collections::VecDeque;

    /// blake2b-256 hasher for CRDT CIDs. Uses blake2b_simd (already a
    /// vos dep) with a configurable 32-byte output length.
    ///
    /// blake2b is the hash of choice for VOS actors: the on-chain
    /// host exposes a precompile for it and the in-progress
    /// zkVM has a dedicated circuit. Matching CRDT CIDs to those
    /// pieces keeps the moving parts aligned.
    pub struct Blake2b;

    impl Hasher for Blake2b {
        type Output = [u8; 32];
        fn hash(data: &[u8]) -> [u8; 32] {
            let hash = blake2b_simd::Params::new().hash_length(32).hash(data);
            hash.as_bytes()
                .try_into()
                .expect("blake2b configured for 32-byte output")
        }
    }

    // ── merkle-crdt Encode/Decode for CrdtEvent ─────────────────────
    //
    // The DagNode payload is `CrdtEvent`, which wraps an EffectLog
    // with `(origin, seq)` metadata so two replicas independently
    // producing byte-identical EffectLogs land on distinct CIDs.
    // CrdtEvent carries its own self-describing encoding via
    // to_bytes / from_bytes; inside a DagNode the payload sits in
    // its own length-prefixed slot, so the decoder receives exactly
    // the payload bytes and we can consume the whole slice.

    impl McEncode for CrdtEvent {
        fn encode_to(&self, buf: &mut Vec<u8>) {
            buf.extend_from_slice(&self.to_bytes());
        }
    }

    impl McDecode for CrdtEvent {
        fn decode_from(buf: &[u8], pos: &mut usize) -> Option<Self> {
            let slice = &buf[*pos..];
            *pos = buf.len();
            CrdtEvent::from_bytes(slice)
        }
    }

    /// redb table holding merkle-DAG nodes keyed by CID bytes.
    /// Uses the same name as [`merkle_crdt::RedbStore`] so a
    /// `RedbStore` opened against this database sees the same nodes.
    pub const DAG_TABLE: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("dag");

    /// Row key in [`STATE_TABLE`](super::STATE_TABLE) for the
    /// serialized Merkle-Clock roots.
    pub const ROOTS_KEY: &str = "crdt_roots";

    /// Row key in [`STATE_TABLE`](super::STATE_TABLE) for the
    /// per-origin monotone sequence counter. Allocated under the
    /// commit lock when the strategy writes a new DAG node;
    /// persisted alongside `STATE_KEY` and `ROOTS_KEY` so a crash
    /// can't reuse a `seq` value across restarts.
    pub const NEXT_SEQ_KEY: &str = "crdt_next_seq";

    /// Merkle-CRDT commit strategy.
    ///
    /// On every `commit_with_log`, writes the actor's state, the new
    /// DAG node (payload = [`EffectLog`]), and the updated roots
    /// list in a single redb write transaction. A crash between
    /// dispatches leaves the three in sync. On `restore`, returns
    /// the materialized state bytes; if absent, the host calls
    /// [`replay_logs`](CommitStrategy::replay_logs) to rebuild state
    /// via a runtime replay session.
    pub struct CrdtCommit {
        db: alloc::sync::Arc<redb::Database>,
        clock: MerkleClock<Blake2b>,
        last_state: Vec<u8>,
        /// Serializes the agent's commits with the sync ticker's
        /// inserts/compactions when multiple `CrdtCommit`s share
        /// the same database. The lock is held only for the
        /// duration of one write — both paths refresh `clock` /
        /// `last_state` from disk inside the critical section so
        /// the view they write against is always the latest.
        ///
        /// When a strategy isn't shared (regular `open` / single-
        /// node Local-style use), the lock is a fresh per-instance
        /// `Mutex` that's always uncontended.
        commit_lock: alloc::sync::Arc<std::sync::Mutex<()>>,
        /// Per-replica origin id stamped onto every `CrdtEvent` we
        /// produce. Distinct per replica (typically derived from
        /// the host node's identity), so two replicas of the *same*
        /// replication group still write events with different
        /// origins — the merkle-DAG keeps both as separate nodes
        /// instead of dedup'ing them by content. Stable across
        /// restarts of the same replica so warm-starts continue
        /// the same `(origin, seq)` chain.
        replica_origin: [u8; 32],
        /// Per-origin monotone counter. Loaded from
        /// `STATE_TABLE/NEXT_SEQ_KEY` on open and incremented under
        /// `commit_lock` for every state-changing commit. Persisted
        /// in the same write-txn as the new DAG node so a crash
        /// can't reuse a `seq` value.
        next_seq: u64,
        /// Optional gate on peer-merged nodes (see
        /// [`NodeValidator`](super::NodeValidator)). `None` accepts all.
        node_validator: Option<super::NodeValidator>,
    }

    impl CrdtCommit {
        /// Open (or create) the redb database at `path` and load the
        /// Merkle-Clock roots from its `state` table. `replica_origin`
        /// is required and gets stamped onto every event this strategy
        /// produces. It must differ across replicas of the same group
        /// — pick it from the host's identity (e.g. node prefix or
        /// libp2p peer-id hash); the replication-group id is the wrong
        /// choice because every replica in a group shares it.
        pub fn open(path: &std::path::Path, replica_origin: [u8; 32]) -> Result<Self, CommitError> {
            let db = alloc::sync::Arc::new(redb::Database::create(path)?);
            Ok(Self::with_state(
                db,
                alloc::sync::Arc::new(std::sync::Mutex::new(())),
                replica_origin,
            ))
        }

        /// Build a `CrdtCommit` on a pre-opened, shared
        /// `Arc<redb::Database>`. Used when the host wants the
        /// same database exposed to a parallel reader (e.g. a
        /// `SyncHandler`) without double-opening — redb is
        /// exclusive on file open, so this is the only way to
        /// share access.
        ///
        /// The returned strategy gets a fresh per-instance commit
        /// lock; use [`from_db_arc_locked`](Self::from_db_arc_locked)
        /// when multiple `CrdtCommit`s over the same db need to
        /// serialize their writes (agent thread + sync ticker).
        pub fn from_db_arc(db: alloc::sync::Arc<redb::Database>, replica_origin: [u8; 32]) -> Self {
            Self::with_state(
                db,
                alloc::sync::Arc::new(std::sync::Mutex::new(())),
                replica_origin,
            )
        }

        /// Build a `CrdtCommit` sharing both an `Arc<Database>`
        /// AND an `Arc<Mutex<()>>` with another instance — agent
        /// thread + sync ticker both pointing at the same redb
        /// file need this to serialize the agent's
        /// `commit_with_log` against the ticker's
        /// `insert_node` + `compact_roots`.
        pub fn from_db_arc_locked(
            db: alloc::sync::Arc<redb::Database>,
            commit_lock: alloc::sync::Arc<std::sync::Mutex<()>>,
            replica_origin: [u8; 32],
        ) -> Self {
            Self::with_state(db, commit_lock, replica_origin)
        }

        fn with_state(
            db: alloc::sync::Arc<redb::Database>,
            commit_lock: alloc::sync::Arc<std::sync::Mutex<()>>,
            replica_origin: [u8; 32],
        ) -> Self {
            let clock = load_clock(&db).unwrap_or_default();
            let last_state = load_state(&db).unwrap_or_default();
            let next_seq = load_next_seq(&db).unwrap_or(0);
            Self {
                db,
                clock,
                last_state,
                commit_lock,
                replica_origin,
                next_seq,
                node_validator: None,
            }
        }

        /// Install a [`NodeValidator`](super::NodeValidator) that gates
        /// every peer-merged node in [`insert_node`](Self::insert_node).
        pub fn set_node_validator(&mut self, validator: Option<super::NodeValidator>) {
            self.node_validator = validator;
        }

        /// Borrow the underlying redb database.
        pub fn db(&self) -> &redb::Database {
            &self.db
        }

        /// Clone of the underlying redb database `Arc`. Lets the
        /// network sync layer read DAG nodes off this commit
        /// strategy concurrently with the agent thread writing
        /// new ones — redb serializes writes internally and
        /// supports concurrent readers.
        pub fn db_arc(&self) -> alloc::sync::Arc<redb::Database> {
            self.db.clone()
        }

        /// Borrow the in-memory Merkle-Clock.
        pub fn clock(&self) -> &MerkleClock<Blake2b> {
            &self.clock
        }

        /// Current root CIDs as raw 32-byte arrays — the wire
        /// format `Frame::Heads` uses.
        pub fn root_bytes(&self) -> Vec<[u8; 32]> {
            self.clock.roots().iter().map(|cid| cid.0).collect()
        }

        /// Read a single DAG node's serialized bytes from the
        /// store. `Ok(None)` means the CID isn't in the local
        /// DAG (typical during sync — peer has nodes we don't).
        pub fn get_node_bytes(&self, cid: &[u8; 32]) -> Result<Option<Vec<u8>>, CommitError> {
            read_dag_node(&self.db, cid)
        }

        /// Insert a DAG node received from a peer. Self-verifies
        /// the CID, writes the node atomically, then adds the CID
        /// to the in-memory clock as a candidate root. Caller
        /// should run [`compact_roots`](Self::compact_roots)
        /// after a batch of inserts to drop ancestor roots.
        ///
        /// Returns `Ok(true)` when the node was new, `Ok(false)`
        /// when we already had it.
        pub fn insert_node(
            &mut self,
            cid: &[u8; 32],
            node_bytes: &[u8],
        ) -> Result<bool, CommitError> {
            let recomputed = Blake2b::hash(node_bytes);
            if &recomputed != cid {
                return Err(CommitError::Config(alloc::format!(
                    "insert_node: CID mismatch (claimed {cid:02x?}, recomputed {recomputed:02x?})"
                )));
            }
            // Per-replica gate: drop a peer node the replica must not
            // trust (e.g. a forged genesis whose CID doesn't derive the
            // space_id). Dropped, not errored — one bad node mustn't
            // abort the whole sync. The honest node's own commits go
            // through `write_atomic`, not here, so this only filters
            // peer-merged ingress.
            if let Some(validator) = &self.node_validator
                && !validator(cid, node_bytes)
            {
                log::warn!("insert_node: rejected peer node {cid:02x?} (failed replica validator)");
                return Ok(false);
            }
            // Quick existence check — avoids a write txn for
            // duplicates (which is the common case during gossip).
            if read_dag_node(&self.db, cid)?.is_some() {
                return Ok(false);
            }
            // Serialize with concurrent commit_with_log on the agent
            // thread so we never split the (DAG node + ROOTS_KEY)
            // pair across an agent write.
            let _guard = self.commit_lock.lock().expect("commit_lock poisoned");
            let txn = self.db.begin_write()?;
            {
                let mut table = txn.open_table(DAG_TABLE)?;
                table.insert(cid.as_slice(), node_bytes)?;
            }
            txn.commit()?;
            self.clock.add_roots(core::iter::once(Cid::<Blake2b>(*cid)));
            Ok(true)
        }

        /// Drop ancestor roots — after a batch of `insert_node`
        /// calls, some roots may be subsumed by others. Walks the
        /// DAG to find and remove subsumed roots, then persists
        /// the new root set to the state table so the next
        /// `restore` sees it.
        pub fn compact_roots(&mut self) -> Result<(), CommitError> {
            // We walk via direct redb access (rather than
            // RedbStore) to avoid double-opening the database.
            // Pure read transaction — safe to overlap with writes.
            //
            // Serialize with the agent's commit_with_log: union
            // our in-memory candidates with the persisted root
            // set so a concurrent agent commit's new root isn't
            // dropped from ROOTS_KEY when we write back.
            let _guard = self.commit_lock.lock().expect("commit_lock poisoned");
            let persisted = load_clock(&self.db).unwrap_or_default();
            self.clock.add_roots(persisted.roots().iter().cloned());
            let candidates = self.clock.roots().clone();
            if candidates.len() <= 1 {
                return self.persist_roots();
            }
            let mut subsumed = BTreeSet::new();
            let mut visited = BTreeSet::new();
            let mut stack: Vec<Cid<Blake2b>> = candidates.iter().cloned().collect();

            let txn = self.db.begin_read()?;
            let table = match txn.open_table(DAG_TABLE) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => {
                    return self.persist_roots();
                }
                Err(e) => return Err(e.into()),
            };
            while let Some(cid) = stack.pop() {
                if !visited.insert(cid.clone()) {
                    continue;
                }
                let Some(val) = table.get(cid.as_ref())? else {
                    continue;
                };
                let node: DagNode<Blake2b, CrdtEvent> = DagNode::from_bytes(val.value())
                    .ok_or_else(|| {
                        CommitError::Config(alloc::format!(
                            "compact_roots: node {cid:?} could not be decoded",
                        ))
                    })?;
                for child in &node.children {
                    if candidates.contains(child) {
                        subsumed.insert(child.clone());
                    }
                    if !visited.contains(child) {
                        stack.push(child.clone());
                    }
                }
            }
            drop(table);
            drop(txn);

            let new_roots: BTreeSet<Cid<Blake2b>> =
                candidates.difference(&subsumed).cloned().collect();
            self.clock = MerkleClock::new();
            self.clock.add_roots(new_roots);
            self.persist_roots()
        }

        /// Materialize state from the (possibly newly-merged) DAG
        /// by re-running the existing `replay_logs` machinery.
        /// Convenience for sync flows that just inserted nodes
        /// and want the strategy's notion of state to catch up.
        pub fn refresh_last_state(&mut self, state: Vec<u8>) {
            self.last_state = state;
        }

        fn persist_roots(&self) -> Result<(), CommitError> {
            let bytes = encode_roots(self.clock.roots());
            let txn = self.db.begin_write()?;
            {
                let mut table = txn.open_table(STATE_TABLE)?;
                table.insert(ROOTS_KEY, bytes.as_slice())?;
            }
            txn.commit()?;
            Ok(())
        }
    }

    /// Read a single DAG node's serialized bytes by CID from a
    /// shared redb database. Public so a `SyncHandler` (or any
    /// other reader) can serve fetches without holding a
    /// `CrdtCommit` mutex.
    pub fn read_dag_node(
        db: &redb::Database,
        cid: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, CommitError> {
        let txn = db.begin_read()?;
        let table = match txn.open_table(DAG_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Ok(table.get(cid.as_slice())?.map(|v| v.value().to_vec()))
    }

    /// Read the persisted root CIDs as raw 32-byte arrays. Returns
    /// the most recent committed roots — slightly stale relative
    /// to the in-memory `MerkleClock`, but correct enough for
    /// sync (which doesn't race with in-flight commits anyway).
    pub fn read_roots(db: &redb::Database) -> Result<Vec<[u8; 32]>, CommitError> {
        let txn = db.begin_read()?;
        let table = match txn.open_table(STATE_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let bytes = match table.get(ROOTS_KEY)? {
            Some(val) => val.value().to_vec(),
            None => return Ok(Vec::new()),
        };
        let Some(roots) = decode_roots(&bytes) else {
            return Ok(Vec::new());
        };
        Ok(roots.into_iter().map(|cid| cid.0).collect())
    }

    impl CommitStrategy for CrdtCommit {
        fn pending_invocation_id(&self) -> Option<crate::v2::InvocationId> {
            Some(CrdtEvent::invocation_id_for(
                self.replica_origin,
                self.next_seq,
            ))
        }

        fn restore(&mut self) -> Option<Vec<u8>> {
            // last_state was populated on open; re-load is not needed.
            if self.last_state.is_empty() {
                None
            } else {
                Some(self.last_state.clone())
            }
        }

        fn commit(&mut self, delta: &AgentDelta<'_>) -> Result<CommitReceipt, CommitError> {
            self.write_atomic(delta)
        }

        fn commit_rebuilt(
            &mut self,
            state: &[u8],
            rows: &[(Vec<u8>, Vec<u8>)],
        ) -> Result<CommitReceipt, CommitError> {
            // Serialize against the sync ticker like write_atomic does —
            // it only inserts DAG nodes and ROOTS, never STATE or KV
            // rows, but sharing the lock keeps every writer to this db
            // on one discipline. Replay materializes history the DAG
            // already carries, so ROOTS/NEXT_SEQ stay untouched and no
            // node appends.
            let _guard = self.commit_lock.lock().expect("commit_lock poisoned");
            let txn = self.db.begin_write()?;
            {
                let mut table = txn.open_table(STATE_TABLE)?;
                table.insert(STATE_KEY, state)?;
            }
            super::swap_kv_rows(&txn, rows)?;
            txn.commit()?;
            self.last_state = state.to_vec();
            Ok(CommitReceipt {
                node_appended: false,
            })
        }

        fn restore_writes(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, CommitError> {
            super::read_kv_rows(&self.db)
        }

        fn reload(&mut self) -> Result<(), CommitError> {
            // Pick up roots and state the parallel sync ticker may
            // have written to disk while we were idle. The clock
            // reflects the merged head set; last_state goes back
            // to whatever's persisted (which sync never overwrites
            // — only the agent commits state).
            self.clock = load_clock(&self.db).unwrap_or_default();
            self.last_state = load_state(&self.db).unwrap_or_default();
            Ok(())
        }

        fn roots(&self) -> Vec<[u8; 32]> {
            self.root_bytes()
        }

        fn needs_sync_reload(&self) -> bool {
            // After our own `write_atomic`, the in-memory clock is set to the
            // freshly-committed roots, which is exactly what we persisted — so
            // an equal root set means the sync signal is the echo of our own
            // commit and there is nothing to fold in. A genuine remote merge
            // (the sync ticker's `insert_node` + `compact_roots`, or a follower
            // applying the leader's entries) advances the persisted roots past
            // our clock, so the sets differ and we reload to converge. This is
            // conservative: it never skips a real merge (any divergence reloads),
            // it only drops the redundant self-commit restart.
            let persisted = load_clock(&self.db).unwrap_or_else(MerkleClock::new);
            self.clock.roots() != persisted.roots()
        }

        fn replay_logs(&self) -> Result<Vec<EffectLog>, CommitError> {
            // BFS from roots, collect all reachable nodes, then
            // topological sort so predecessors come before
            // successors. Each node's payload is a `CrdtEvent`;
            // we unwrap to its inner `EffectLog` for the runtime,
            // which only cares about the dispatch + replies.
            // `(origin, seq)` stay on disk — replays don't
            // re-stamp them.
            let mut nodes: BTreeMap<Cid<Blake2b>, DagNode<Blake2b, CrdtEvent>> = BTreeMap::new();
            let mut stack: Vec<Cid<Blake2b>> = self.clock.roots().iter().cloned().collect();

            let txn = self.db.begin_read()?;
            let table = match txn.open_table(DAG_TABLE) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(e.into()),
            };

            while let Some(cid) = stack.pop() {
                if nodes.contains_key(&cid) {
                    continue;
                }
                // A child CID that doesn't resolve to a stored node is a
                // dangling causal reference. This happens two legitimate
                // ways and one hostile way, and replay must survive all
                // three rather than abort:
                //   * sync fetches heads→parents, so a node can land
                //     before its parents have synced in;
                //   * a forged peer node can cite a parent that was never
                //     produced (children = {random CID}) — `insert_node`
                //     only checks CID==hash(bytes), and `compact_roots`
                //     already tolerates the missing child, so the bogus
                //     node reaches replay.
                // Hard-erroring here would set the agent's `fatal_error`
                // and brick *every* cold restart (the forged node persists
                // in redb) — a member-triggerable DoS. Instead skip the
                // unresolved node, exactly as `compact_roots` does. Its
                // children are simply absent from `nodes`, so
                // `topological_order` quarantines any node that depends on
                // them (their indegree never reaches 0) without applying
                // it. Once the real parents sync in, the next replay walks
                // the now-complete chain.
                let Some(val) = table.get(cid.as_ref())? else {
                    continue;
                };
                let bytes = val.value();
                let Some(node) = DagNode::<Blake2b, CrdtEvent>::from_bytes(bytes) else {
                    // Present but undecodable — local corruption, or a peer
                    // node whose bytes hash to their CID yet aren't a valid
                    // `DagNode` encoding. Same DoS class, same fail-safe:
                    // skip rather than abort the whole replay.
                    log::warn!("replay_logs: skipping undecodable DAG node {cid:02x?}");
                    continue;
                };
                for child in &node.children {
                    if !nodes.contains_key(child) {
                        stack.push(child.clone());
                    }
                }
                nodes.insert(cid, node);
            }
            drop(table);
            drop(txn);

            Ok(topological_order(nodes))
        }
    }

    impl CrdtCommit {
        fn write_atomic(&mut self, delta: &AgentDelta<'_>) -> Result<CommitReceipt, CommitError> {
            let (state, rest) = super::split_delta(delta);
            let state_changed = state.is_some_and(|s| s != self.last_state.as_slice());

            // The durable-node rule (work-result contract §4): a
            // dispatch whose payload carried no effects is a pure read
            // — nothing persists, no node appends, no `seq` allocates.
            // An effect-bearing dispatch appends a node even when the
            // state blob is unchanged (a Transfer-only dispatch is
            // real history that replay must reproduce). v2 deltas
            // (`effect_bearing == false`) fall back to value
            // comparison, since those guests re-emit their full state
            // on every halt — but a v2 dispatch that wrote KV rows
            // under an unchanged state blob still appends: every
            // persisted row must be replay-derivable, or the next
            // post-replay materialization (`commit_rebuilt`'s
            // whole-table swap) destroys it. RaftCommit's guard
            // already includes `rest`.
            let append_node =
                delta.log.is_some() && (state_changed || delta.effect_bearing || !rest.is_empty());
            if !state_changed && rest.is_empty() && !append_node {
                return Ok(CommitReceipt {
                    node_appended: false,
                });
            }

            // Hold the commit lock across "compute new DAG node
            // referencing current roots" + "write {state, ROOTS_KEY,
            // NEXT_SEQ_KEY, new node}" so a concurrent sync ticker
            // can't insert a peer node and update ROOTS_KEY between
            // the read of self.clock.roots() and our write back.
            // Refresh the clock and next_seq from disk under the
            // lock so we see anything the ticker just merged in
            // and don't reuse a `seq` after an out-of-band restart.
            let _guard = self.commit_lock.lock().expect("commit_lock poisoned");
            self.clock = load_clock(&self.db).unwrap_or_default();
            // `next_seq` lives only in our own writes — the sync
            // ticker never advances it — but reload defensively in
            // case a separate process touched the file.
            self.next_seq = load_next_seq(&self.db).unwrap_or(self.next_seq);

            if append_node {
                let log = delta.log.expect("append_node implies a log");
                let expected = CrdtEvent::invocation_id_for(self.replica_origin, self.next_seq);
                if log.invocation_id() != crate::v2::InvocationId::ZERO
                    && log.invocation_id() != expected
                {
                    return Err(CommitError::Config(
                        "CRDT dispatch invocation no longer matches the durable event sequence"
                            .into(),
                    ));
                }
            }

            // Compute the new DAG node (if any) off-transaction so
            // the write txn is short. Wrap the EffectLog in a
            // CrdtEvent stamped with our origin + the next seq so
            // the resulting CID is globally unique even when other
            // replicas commit byte-identical EffectLogs concurrently.
            let new_cid_bytes_seq = append_node
                .then(|| delta.log.expect("append_node implies a log"))
                .map(|log| {
                    let event = CrdtEvent::new(self.replica_origin, self.next_seq, log.clone());
                    let children = self.clock.roots().clone();
                    let node = DagNode::new(event, children);
                    let cid = node.cid();
                    let bytes = node.to_bytes();
                    let allocated_seq = self.next_seq;
                    (cid, bytes, allocated_seq)
                });

            let roots_bytes = match &new_cid_bytes_seq {
                Some((cid, _, _)) => {
                    let mut roots = BTreeSet::new();
                    roots.insert(cid.clone());
                    encode_roots(&roots)
                }
                None => encode_roots(self.clock.roots()),
            };

            let next_seq_after = self.next_seq + new_cid_bytes_seq.is_some() as u64;

            let txn = self.db.begin_write()?;
            {
                let mut state_table = txn.open_table(STATE_TABLE)?;
                if state_changed
                    && let Some(state) = state
                {
                    state_table.insert(STATE_KEY, state)?;
                }
                state_table.insert(ROOTS_KEY, roots_bytes.as_slice())?;
                state_table.insert(NEXT_SEQ_KEY, next_seq_after.to_le_bytes().as_slice())?;

                if !rest.is_empty() {
                    let mut kv = txn.open_table(super::KV_TABLE)?;
                    for (key, value) in &rest {
                        match value {
                            Some(value) => {
                                kv.insert(*key, *value)?;
                            }
                            None => {
                                kv.remove(*key)?;
                            }
                        }
                    }
                }
                if let Some((cid, bytes, _)) = &new_cid_bytes_seq {
                    let mut dag_table = txn.open_table(DAG_TABLE)?;
                    dag_table.insert(cid.as_ref(), bytes.as_slice())?;
                }
            }
            txn.commit()?;

            // Update in-memory clock to reflect the newly committed
            // roots. For a node-less commit the roots are unchanged.
            let node_appended = new_cid_bytes_seq.is_some();
            if let Some((cid, _, _)) = new_cid_bytes_seq {
                self.clock = MerkleClock::new();
                self.clock.add_roots(core::iter::once(cid));
            }
            self.next_seq = next_seq_after;
            if state_changed
                && let Some(state) = state
            {
                self.last_state = state.to_vec();
            }
            Ok(CommitReceipt { node_appended })
        }
    }

    // ── helpers ─────────────────────────────────────────────────────

    fn load_state(db: &redb::Database) -> Option<Vec<u8>> {
        let txn = db.begin_read().ok()?;
        let table = txn.open_table(STATE_TABLE).ok()?;
        let val = table.get(STATE_KEY).ok().flatten()?;
        Some(val.value().to_vec())
    }

    fn load_clock(db: &redb::Database) -> Option<MerkleClock<Blake2b>> {
        let txn = db.begin_read().ok()?;
        let table = txn.open_table(STATE_TABLE).ok()?;
        let val = table.get(ROOTS_KEY).ok().flatten()?;
        let bytes = val.value();
        decode_roots(bytes).map(|roots| {
            let mut c = MerkleClock::new();
            c.add_roots(roots);
            c
        })
    }

    fn load_next_seq(db: &redb::Database) -> Option<u64> {
        let txn = db.begin_read().ok()?;
        let table = txn.open_table(STATE_TABLE).ok()?;
        let val = table.get(NEXT_SEQ_KEY).ok().flatten()?;
        let bytes = val.value();
        if bytes.len() != 8 {
            return None;
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(bytes);
        Some(u64::from_le_bytes(arr))
    }

    /// Encode a root set as `[count:u64 LE][cid_bytes (32 each)...]`.
    fn encode_roots(roots: &BTreeSet<Cid<Blake2b>>) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + roots.len() * 32);
        buf.extend_from_slice(&(roots.len() as u64).to_le_bytes());
        for cid in roots {
            buf.extend_from_slice(cid.as_ref());
        }
        buf
    }

    fn decode_roots(bytes: &[u8]) -> Option<BTreeSet<Cid<Blake2b>>> {
        if bytes.len() < 8 {
            return None;
        }
        let count = u64::from_le_bytes(bytes[..8].try_into().ok()?) as usize;
        if bytes.len() != 8 + count * 32 {
            return None;
        }
        let mut set = BTreeSet::new();
        for i in 0..count {
            let start = 8 + i * 32;
            let arr: [u8; 32] = bytes[start..start + 32].try_into().ok()?;
            set.insert(Cid::<Blake2b>(arr));
        }
        Some(set)
    }

    /// Kahn's algorithm over the reachable DAG subset.
    ///
    /// In merkle-crdt, a node's `children` field holds its causal
    /// predecessors (older events). We want output order such that
    /// predecessors come before successors — so the "edge" for
    /// Kahn's purposes points from each child (predecessor) to the
    /// node that lists it. A node with 0 children is an origin and
    /// is emitted first.
    ///
    /// Returns just the inner [`EffectLog`]s — the runtime's replay path
    /// consumes those directly. [`CrdtEvent::new`] /
    /// [`CrdtEvent::from_bytes`] have already reconstructed the stable
    /// handler-visible invocation identity from `origin` and `seq`.
    fn topological_order(
        mut nodes: BTreeMap<Cid<Blake2b>, DagNode<Blake2b, CrdtEvent>>,
    ) -> Vec<EffectLog> {
        // indegree[n] = number of children of n — i.e. how many
        // predecessors it depends on.
        let mut indegree: BTreeMap<Cid<Blake2b>, usize> = BTreeMap::new();
        // reverse[pred] = list of nodes that declare `pred` as a child.
        let mut reverse: BTreeMap<Cid<Blake2b>, Vec<Cid<Blake2b>>> = BTreeMap::new();

        for (cid, node) in &nodes {
            indegree.insert(cid.clone(), node.children.len());
            for child in &node.children {
                reverse.entry(child.clone()).or_default().push(cid.clone());
            }
        }

        let mut queue: VecDeque<Cid<Blake2b>> = indegree
            .iter()
            .filter(|(_, d)| **d == 0)
            .map(|(c, _)| c.clone())
            .collect();

        let mut sorted = Vec::with_capacity(nodes.len());
        while let Some(cid) = queue.pop_front() {
            if let Some(node) = nodes.remove(&cid) {
                sorted.push(node.payload.log);
            }
            if let Some(successors) = reverse.get(&cid) {
                for succ in successors {
                    if let Some(d) = indegree.get_mut(succ) {
                        *d = d.saturating_sub(1);
                        if *d == 0 {
                            queue.push_back(succ.clone());
                        }
                    }
                }
            }
        }
        sorted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_commit_restore_none() {
        let mut s = NoCommit;
        assert!(s.restore().is_none());
        assert!(s.commit_state(b"anything").is_ok());
    }

    #[cfg(feature = "storage")]
    fn temp_db_path(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vos_commit_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("db.redb")
    }

    #[cfg(feature = "storage")]
    #[test]
    fn crdt_commit_preserves_state_and_replays_in_order() {
        use crate::effect_log::EffectLog;

        let path = temp_db_path("crdt_order");

        // Three dispatches, each writing a monotonically-growing
        // state blob and a distinct effect log.
        let mut logs = Vec::new();
        {
            let mut cc = CrdtCommit::open(&path, [0u8; 32]).unwrap();
            assert!(cc.restore().is_none(), "fresh db has no state");

            let mk = |msg: &[u8], replies: &[&[u8]]| -> EffectLog {
                let mut l = EffectLog::for_msg(msg.to_vec());
                for r in replies {
                    l.record_reply(r.to_vec());
                }
                l
            };

            logs.push(mk(b"msg-1", &[b"r1a"]));
            logs.push(mk(b"msg-2", &[b"r2a", b"r2b"]));
            logs.push(mk(b"msg-3", &[]));

            cc.commit_with_log(b"state-v1", &logs[0]).unwrap();
            cc.commit_with_log(b"state-v2", &logs[1]).unwrap();
            cc.commit_with_log(b"state-v3", &logs[2]).unwrap();

            assert_eq!(cc.clock().roots().len(), 1, "a linear chain has one head");
        }

        // Reopen: state + roots restore, replay_logs walks the DAG
        // and hands back all three logs in causal order.
        {
            let mut cc = CrdtCommit::open(&path, [0u8; 32]).unwrap();
            assert_eq!(cc.restore().as_deref(), Some(&b"state-v3"[..]));
            assert_eq!(cc.clock().roots().len(), 1);

            let replay = cc.replay_logs().unwrap();
            assert_eq!(replay.len(), 3);
            for (seq, (replayed, original)) in replay.iter().zip(&logs).enumerate() {
                assert_eq!(replayed.msg, original.msg);
                assert_eq!(replayed.replies, original.replies);
                assert_eq!(
                    replayed.invocation_id(),
                    crate::effect_log::CrdtEvent::invocation_id_for([0u8; 32], seq as u64),
                );
            }
        }

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[cfg(feature = "storage")]
    #[test]
    fn crdt_commit_reload_picks_up_external_writes() {
        // Two `CrdtCommit` instances share the same `Arc<redb::Database>`.
        // The "agent" half drives state forward; the "sync" half
        // simulates a peer pulling a remote node by calling
        // `insert_node` directly. After `reload`, the agent's view
        // of `roots` includes the merged head, and `replay_logs`
        // returns both the agent's own log and the simulated
        // peer's log in causal order.
        use crate::effect_log::EffectLog;
        use std::collections::BTreeSet;

        let path = temp_db_path("crdt_reload");
        let arc = alloc::sync::Arc::new(redb::Database::create(&path).unwrap());

        let mut agent = CrdtCommit::from_db_arc(arc.clone(), [0u8; 32]);
        let mut sync = CrdtCommit::from_db_arc(arc.clone(), [0u8; 32]);

        // Agent commits one log. After this, agent.clock has one root,
        // sync's clock is still empty (won't see it without reload).
        let log_a = EffectLog::for_msg(b"local".to_vec());
        agent.commit_with_log(b"state-a", &log_a).unwrap();
        assert_eq!(agent.root_bytes().len(), 1);
        assert!(sync.root_bytes().is_empty(), "sync hasn't reloaded yet");

        // sync.reload() picks up agent's persisted root.
        sync.reload().unwrap();
        assert_eq!(sync.root_bytes(), agent.root_bytes());

        // Build a "remote" log node manually and feed it through
        // sync.insert_node — mimics what the cycle-3 ticker does.
        // It should be a sibling of the agent's existing root
        // (no children → concurrent). The remote replica's
        // origin/seq just need to differ from ours; a fixed
        // [1u8; 32] origin is enough to distinguish.
        use crate::effect_log::CrdtEvent;
        let log_b = EffectLog::for_msg(b"remote".to_vec());
        let remote_event = CrdtEvent::new([1u8; 32], 0, log_b.clone());
        let remote_node: merkle_crdt::DagNode<Blake2b, CrdtEvent> =
            merkle_crdt::DagNode::new(remote_event, BTreeSet::new());
        let remote_cid = remote_node.cid();
        let remote_bytes = remote_node.to_bytes();
        let was_new = sync.insert_node(&remote_cid.0, &remote_bytes).unwrap();
        assert!(was_new);
        sync.compact_roots().unwrap();

        // Now the disk has TWO roots (concurrent siblings). Agent
        // hasn't reloaded yet; its clock still shows just the
        // local root.
        assert_eq!(agent.root_bytes().len(), 1);

        // After reload, agent sees the merged set.
        agent.reload().unwrap();
        let mut roots = agent.root_bytes();
        roots.sort();
        assert_eq!(roots.len(), 2);

        // replay_logs returns both effect logs.
        let mut logs = agent.replay_logs().unwrap();
        logs.sort_by(|a, b| a.msg.cmp(&b.msg));
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].msg, b"local");
        assert_eq!(logs[1].msg, b"remote");

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[cfg(feature = "storage")]
    #[test]
    fn insert_node_honors_validator() {
        // A per-replica NodeValidator gates peer-merged nodes: a rejected
        // node is dropped (Ok(false), not stored), an accepted one lands.
        // This is the ingest gate the registry uses to bind its genesis.
        use crate::effect_log::{CrdtEvent, EffectLog};
        use merkle_crdt::DagNode;
        use std::collections::BTreeSet;

        let path = temp_db_path("validator_gate");
        let mut cc = CrdtCommit::open(&path, [0u8; 32]).unwrap();

        let mk = |msg: &[u8], seq: u64| -> ([u8; 32], Vec<u8>) {
            let ev = CrdtEvent::new([1u8; 32], seq, EffectLog::for_msg(msg.to_vec()));
            let node: DagNode<Blake2b, CrdtEvent> = DagNode::new(ev, BTreeSet::new());
            (node.cid().0, node.to_bytes())
        };
        let (good_cid, good_bytes) = mk(b"good", 0);
        let (bad_cid, bad_bytes) = mk(b"bad", 1);

        // Accept only `good_cid`.
        let accept = good_cid;
        cc.set_node_validator(Some(alloc::sync::Arc::new(
            move |cid: &[u8; 32], _b: &[u8]| *cid == accept,
        )));

        assert!(
            !cc.insert_node(&bad_cid, &bad_bytes).unwrap(),
            "rejected node reports not-inserted",
        );
        assert!(
            cc.get_node_bytes(&bad_cid).unwrap().is_none(),
            "rejected node must not be stored",
        );
        assert!(
            cc.insert_node(&good_cid, &good_bytes).unwrap(),
            "accepted node is inserted",
        );
        assert!(cc.get_node_bytes(&good_cid).unwrap().is_some());

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[cfg(feature = "storage")]
    #[test]
    fn replay_logs_quarantines_dangling_parent() {
        // A peer (or a forging member) can inject a DAG node that cites a
        // parent which was never produced: `insert_node` accepts it on the
        // CID-only check, and `compact_roots` already tolerates the missing
        // child. Replay must NOT hard-error on the unresolved parent — doing
        // so sets the agent's fatal_error and bricks every cold restart,
        // which is a member-triggerable DoS. Instead the orphaned node is
        // quarantined (skipped) and the rest of the DAG replays.
        use crate::effect_log::{CrdtEvent, EffectLog};
        use merkle_crdt::{Cid, DagNode, Hasher};
        use std::collections::BTreeSet;

        let path = temp_db_path("dangling_parent");
        let mut cc = CrdtCommit::open(&path, [0u8; 32]).unwrap();

        // A real two-event chain (one head).
        let log1 = EffectLog::for_msg(b"real-1".to_vec());
        let log2 = EffectLog::for_msg(b"real-2".to_vec());
        cc.commit_with_log(b"state-1", &log1).unwrap();
        cc.commit_with_log(b"state-2", &log2).unwrap();
        assert_eq!(cc.root_bytes().len(), 1, "linear chain → one head");

        // Forge a node whose only parent is a CID that was never inserted.
        let dangling = Cid::<Blake2b>(Blake2b::hash(b"this-parent-never-existed"));
        let mut children = BTreeSet::new();
        children.insert(dangling);
        let forged_event = CrdtEvent::new([0xAA; 32], 0, EffectLog::for_msg(b"forged".to_vec()));
        let forged_node: DagNode<Blake2b, CrdtEvent> = DagNode::new(forged_event, children);
        let forged_cid = forged_node.cid();
        let forged_bytes = forged_node.to_bytes();

        // Ingest accepts it (CID == hash(bytes); no validator installed) and
        // compaction leaves it as a second, dangling head.
        assert!(
            cc.insert_node(&forged_cid.0, &forged_bytes).unwrap(),
            "forged node passes the CID-only ingest check",
        );
        cc.compact_roots().unwrap();
        assert!(
            cc.get_node_bytes(&forged_cid.0).unwrap().is_some(),
            "forged node is stored in the DAG (accepted at ingest)",
        );
        assert_eq!(cc.root_bytes().len(), 2, "real head + dangling forged head");

        // Replay survives: it returns the real chain and silently drops the
        // node whose parent can't be resolved.
        let logs = cc
            .replay_logs()
            .expect("a dangling parent must not abort replay");
        let msgs: Vec<&[u8]> = logs.iter().map(|l| l.msg.as_slice()).collect();
        assert!(msgs.contains(&&b"real-1"[..]), "real chain still replays");
        assert!(msgs.contains(&&b"real-2"[..]), "real chain still replays");
        assert!(
            !msgs.contains(&&b"forged"[..]),
            "a node citing an unresolvable parent is quarantined, not applied",
        );
        assert_eq!(logs.len(), 2, "only the real chain replays");

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[cfg(feature = "storage")]
    #[test]
    fn crdt_sync_accessors_replicate_dag() {
        // Drive replica A with two dispatches, then have replica B
        // pull A's DAG nodes via the new sync accessors and
        // verify B converges (same roots, replay_logs returns the
        // same logs in the same order).
        use crate::effect_log::{CrdtEvent, EffectLog};
        use merkle_crdt::DagNode;
        use std::collections::BTreeSet;

        let path_a = temp_db_path("crdt_sync_a");
        let path_b = temp_db_path("crdt_sync_b");

        // ── Drive A ────────────────────────────────────────────────
        let mut a = CrdtCommit::open(&path_a, [0u8; 32]).unwrap();
        let log1 = EffectLog::for_msg(b"first".to_vec());
        let log2 = EffectLog::for_msg(b"second".to_vec());
        a.commit_with_log(b"state-1", &log1).unwrap();
        a.commit_with_log(b"state-2", &log2).unwrap();

        let a_roots = a.root_bytes();
        assert_eq!(a_roots.len(), 1, "linear chain → one head");

        // ── Replica B: pull A's nodes via accessors ────────────────
        let mut b = CrdtCommit::open(&path_b, [0u8; 32]).unwrap();
        assert!(b.restore().is_none());
        assert!(b.root_bytes().is_empty());

        // BFS from A's roots, fetch each node, insert into B.
        let mut frontier: Vec<[u8; 32]> = a_roots.clone();
        let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
        while let Some(cid) = frontier.pop() {
            if !seen.insert(cid) {
                continue;
            }
            let bytes = a.get_node_bytes(&cid).unwrap().expect("A has the node");
            let was_new = b.insert_node(&cid, &bytes).unwrap();
            assert!(was_new);
            // Children to walk next
            let node: DagNode<Blake2b, CrdtEvent> = DagNode::from_bytes(&bytes).unwrap();
            for child in node.children {
                frontier.push(child.0);
            }
        }
        b.compact_roots().unwrap();

        // Roots match; replay reproduces A's history.
        let mut a_sorted = a.root_bytes();
        a_sorted.sort();
        let mut b_sorted = b.root_bytes();
        b_sorted.sort();
        assert_eq!(a_sorted, b_sorted);

        let a_logs = a.replay_logs().unwrap();
        let b_logs = b.replay_logs().unwrap();
        assert_eq!(a_logs, b_logs);
        assert_eq!(b_logs.len(), 2);

        // Idempotent re-insert returns false.
        let some_cid = a_roots[0];
        let some_bytes = a.get_node_bytes(&some_cid).unwrap().unwrap();
        let was_new = b.insert_node(&some_cid, &some_bytes).unwrap();
        assert!(!was_new, "re-inserting an existing node is a no-op");

        // Tampered bytes are rejected via CID self-verification.
        let mut tampered = some_bytes.clone();
        tampered[0] ^= 0xFF;
        let bad_cid = some_cid; // claim the same CID for tampered bytes
        let err = b.insert_node(&bad_cid, &tampered);
        assert!(err.is_err(), "tampered node must fail CID check");

        let _ = std::fs::remove_dir_all(path_a.parent().unwrap());
    }

    #[cfg(feature = "storage")]
    #[test]
    fn crdt_commit_skips_unchanged_plain_commits() {
        use crate::effect_log::EffectLog;

        let path = temp_db_path("crdt_skip");
        let mut cc = CrdtCommit::open(&path, [0u8; 32]).unwrap();

        let log = EffectLog::for_msg(b"first".to_vec());
        cc.commit_with_log(b"state", &log).unwrap();
        let roots_after_first = cc.clock().roots().clone();

        // Plain commit with unchanged state — no new DAG node should
        // be appended (roots stay the same).
        cc.commit_state(b"state").unwrap();
        assert_eq!(cc.clock().roots(), &roots_after_first);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[cfg(feature = "storage")]
    #[test]
    fn effect_bearing_unchanged_state_appends_node() {
        // The durable-node rule: a v3 dispatch that carried effects but
        // left the state blob unchanged (e.g. Transfer-only) MUST land
        // in durable history — the pre-A8 skip dropped these entirely.
        // A pure read (no effects) still appends nothing.
        use crate::effect_log::EffectLog;

        let path = temp_db_path("crdt_effect_node");
        let mut cc = CrdtCommit::open(&path, [0u8; 32]).unwrap();

        let writes = [(
            crate::lifecycle::STATE_KEY_BYTES.to_vec(),
            Some(b"state".to_vec()),
        )];
        let log1 = EffectLog::for_msg(b"m1".to_vec());
        let r1 = cc
            .commit(&AgentDelta {
                writes: &writes,
                anchor: (0x00, [0u8; 32]),
                log: Some(&log1),
                effect_bearing: true,
            })
            .unwrap();
        assert!(r1.node_appended, "state-changing dispatch appends");

        // Effect-bearing, state unchanged (no state write in the delta).
        let log2 = EffectLog::for_msg(b"m2".to_vec());
        let r2 = cc
            .commit(&AgentDelta {
                writes: &[],
                anchor: (0x01, [1u8; 32]),
                log: Some(&log2),
                effect_bearing: true,
            })
            .unwrap();
        assert!(
            r2.node_appended,
            "effect-bearing dispatch with unchanged state must produce a durable node"
        );

        // Pure read: no writes, no effects — nothing durable.
        let log3 = EffectLog::for_msg(b"m3".to_vec());
        let r3 = cc
            .commit(&AgentDelta {
                writes: &[],
                anchor: (0x01, [1u8; 32]),
                log: Some(&log3),
                effect_bearing: false,
            })
            .unwrap();
        assert!(!r3.node_appended, "pure reads must not pollute history");

        let logs = cc.replay_logs().unwrap();
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].msg, b"m1");
        assert_eq!(logs[1].msg, b"m2");
        assert_eq!(
            cc.restore().as_deref(),
            Some(&b"state"[..]),
            "state row untouched by the state-unchanged node"
        );

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[cfg(feature = "storage")]
    #[test]
    fn non_state_writes_persist_and_restore() {
        // The whole-agent delta: non-STATE rows land in the KV table in
        // the same txn as the state row and come back via
        // restore_writes on reopen.
        let db_path = temp_db_path("local_kv");
        let dir = db_path.parent().unwrap().to_path_buf();
        {
            let mut lc = LocalCommit::open(&db_path).unwrap();
            let writes = [
                (b"row-a".to_vec(), Some(b"1".to_vec())),
                (
                    crate::lifecycle::STATE_KEY_BYTES.to_vec(),
                    Some(b"state".to_vec()),
                ),
                (b"row-b".to_vec(), Some(b"2".to_vec())),
            ];
            lc.commit(&AgentDelta::state_only(&writes)).unwrap();
        }
        {
            let mut lc = LocalCommit::open(&db_path).unwrap();
            assert_eq!(lc.restore().as_deref(), Some(&b"state"[..]));
            let mut rows = lc.restore_writes().unwrap();
            rows.sort();
            assert_eq!(
                rows,
                vec![
                    (b"row-a".to_vec(), b"1".to_vec()),
                    (b"row-b".to_vec(), b"2".to_vec()),
                ],
                "non-STATE rows must survive a restart"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "storage")]
    #[test]
    fn delete_tombstone_removes_kv_row() {
        // A committed row deleted by a later delta is gone from
        // restore_writes after reopen; deleting an absent row is a
        // no-op, not an error.
        let db_path = temp_db_path("local_kv_delete");
        let dir = db_path.parent().unwrap().to_path_buf();
        {
            let mut lc = LocalCommit::open(&db_path).unwrap();
            let writes = [
                (b"row-a".to_vec(), Some(b"1".to_vec())),
                (b"row-b".to_vec(), Some(b"2".to_vec())),
            ];
            lc.commit(&AgentDelta::state_only(&writes)).unwrap();
            let deletes = [(b"row-a".to_vec(), None), (b"row-c".to_vec(), None)];
            lc.commit(&AgentDelta::state_only(&deletes)).unwrap();
        }
        {
            let lc = LocalCommit::open(&db_path).unwrap();
            assert_eq!(
                lc.restore_writes().unwrap(),
                vec![(b"row-b".to_vec(), b"2".to_vec())],
                "deleted row must not survive a restart"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "storage")]
    #[test]
    fn crdt_delete_tombstone_removes_kv_row() {
        let path = temp_db_path("crdt_kv_delete");
        let mut cc = CrdtCommit::open(&path, [0u8; 32]).unwrap();
        let writes = [(b"row-a".to_vec(), Some(b"1".to_vec()))];
        cc.commit(&AgentDelta::state_only(&writes)).unwrap();
        assert_eq!(
            cc.restore_writes().unwrap(),
            vec![(b"row-a".to_vec(), b"1".to_vec())],
        );
        let deletes = [(b"row-a".to_vec(), None)];
        cc.commit(&AgentDelta::state_only(&deletes)).unwrap();
        assert!(
            cc.restore_writes().unwrap().is_empty(),
            "deleted row must leave the KV table"
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[cfg(feature = "storage")]
    #[test]
    fn crdt_row_writes_under_unchanged_state_append_history() {
        // A v2-style dispatch (effect_bearing = false) that wrote KV
        // rows while re-emitting a byte-identical state blob must
        // append a DAG node: every persisted row has to be
        // replay-derivable, or the next post-replay whole-table swap
        // (commit_rebuilt) destroys it.
        let path = temp_db_path("crdt_v2_rows");
        let mut cc = CrdtCommit::open(&path, [0u8; 32]).unwrap();
        let log1 = crate::effect_log::EffectLog::for_msg(b"m1".to_vec());
        let writes = [(
            crate::lifecycle::STATE_KEY_BYTES.to_vec(),
            Some(b"s".to_vec()),
        )];
        cc.commit(&AgentDelta {
            writes: &writes,
            anchor: (0x01, [1u8; 32]),
            log: Some(&log1),
            effect_bearing: false,
        })
        .unwrap();
        let log2 = crate::effect_log::EffectLog::for_msg(b"m2".to_vec());
        let writes2 = [
            (
                crate::lifecycle::STATE_KEY_BYTES.to_vec(),
                Some(b"s".to_vec()),
            ),
            (b"row".to_vec(), Some(b"1".to_vec())),
        ];
        let receipt = cc
            .commit(&AgentDelta {
                writes: &writes2,
                anchor: (0x01, [2u8; 32]),
                log: Some(&log2),
                effect_bearing: false,
            })
            .unwrap();
        assert!(
            receipt.node_appended,
            "a row-bearing v2 dispatch is real history"
        );
        assert_eq!(cc.replay_logs().unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[cfg(feature = "storage")]
    #[test]
    fn commit_rebuilt_swaps_the_whole_kv_table() {
        // A replay recomputes every row, so commit_rebuilt must clear
        // rows the rebuilt slate no longer produces — an upserting
        // delta commit would leave them behind.
        let db_path = temp_db_path("local_rebuilt");
        let dir = db_path.parent().unwrap().to_path_buf();
        {
            let mut lc = LocalCommit::open(&db_path).unwrap();
            let writes = [
                (b"stale".to_vec(), Some(b"old".to_vec())),
                (b"shared".to_vec(), Some(b"old-layout".to_vec())),
            ];
            lc.commit(&AgentDelta::state_only(&writes)).unwrap();
            lc.commit_rebuilt(
                b"replayed-state",
                &[
                    (b"shared".to_vec(), b"new-layout".to_vec()),
                    (b"fresh".to_vec(), b"from-merge".to_vec()),
                ],
            )
            .unwrap();
        }
        {
            let mut lc = LocalCommit::open(&db_path).unwrap();
            assert_eq!(lc.restore().as_deref(), Some(&b"replayed-state"[..]));
            let mut rows = lc.restore_writes().unwrap();
            rows.sort();
            assert_eq!(
                rows,
                vec![
                    (b"fresh".to_vec(), b"from-merge".to_vec()),
                    (b"shared".to_vec(), b"new-layout".to_vec()),
                ],
                "rows the replay no longer produces must not survive"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "storage")]
    #[test]
    fn crdt_commit_rebuilt_swaps_rows_without_appending_history() {
        let path = temp_db_path("crdt_rebuilt");
        let mut cc = CrdtCommit::open(&path, [0u8; 32]).unwrap();
        let log = crate::effect_log::EffectLog::for_msg(b"m1".to_vec());
        let writes = [
            (
                crate::lifecycle::STATE_KEY_BYTES.to_vec(),
                Some(b"s1".to_vec()),
            ),
            (b"stale".to_vec(), Some(b"old".to_vec())),
        ];
        cc.commit(&AgentDelta {
            writes: &writes,
            anchor: (0x01, [1u8; 32]),
            log: Some(&log),
            effect_bearing: true,
        })
        .unwrap();
        let history = cc.replay_logs().unwrap().len();
        let receipt = cc
            .commit_rebuilt(b"s2", &[(b"fresh".to_vec(), b"1".to_vec())])
            .unwrap();
        assert!(!receipt.node_appended);
        assert_eq!(
            cc.replay_logs().unwrap().len(),
            history,
            "replay materializes history, it must not create any"
        );
        assert_eq!(
            cc.restore_writes().unwrap(),
            vec![(b"fresh".to_vec(), b"1".to_vec())],
            "the pre-replay row must not survive the swap"
        );
        assert_eq!(
            cc.restore().as_deref(),
            Some(&b"s2"[..]),
            "skip-on-unchanged must track the rebuilt state"
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[cfg(feature = "storage")]
    #[test]
    fn split_delta_ignores_state_tombstone() {
        // A STATE_KEY tombstone can't decode off the wire; a host-built
        // delta carrying one must not materialize as a state wipe.
        let writes = [
            (crate::lifecycle::STATE_KEY_BYTES.to_vec(), None),
            (b"row".to_vec(), Some(b"1".to_vec())),
        ];
        let delta = AgentDelta::state_only(&writes);
        let (state, rest) = split_delta(&delta);
        assert_eq!(state, None);
        assert_eq!(rest, vec![(&b"row"[..], Some(&b"1"[..]))]);
    }

    #[cfg(feature = "storage")]
    #[test]
    fn blake2b_hash_is_deterministic() {
        use merkle_crdt::Hasher;
        let a = Blake2b::hash(b"hello");
        let b = Blake2b::hash(b"hello");
        assert_eq!(a, b);
        let c = Blake2b::hash(b"world");
        assert_ne!(a, c);
    }

    #[cfg(feature = "storage")]
    #[test]
    fn trait_defaults_are_no_ops() {
        // NoCommit should ignore commit_with_log and return an empty
        // replay. This is the contract non-replicating strategies
        // rely on.
        use crate::effect_log::EffectLog;
        let mut s = NoCommit;
        let log = EffectLog::for_msg(b"x".to_vec());
        assert!(s.commit_with_log(b"state", &log).is_ok());
        assert!(s.replay_logs().unwrap().is_empty());
    }

    #[cfg(feature = "storage")]
    #[test]
    fn local_commit_roundtrip_and_change_detect() {
        let db_path = temp_db_path("local");
        let dir = db_path.parent().unwrap().to_path_buf();

        // Write, reopen, read back.
        {
            let mut lc = LocalCommit::open(&db_path).unwrap();
            assert!(lc.restore().is_none(), "fresh db has no state");
            lc.commit_state(b"hello").unwrap();
        }
        {
            let mut lc = LocalCommit::open(&db_path).unwrap();
            assert_eq!(lc.restore().as_deref(), Some(&b"hello"[..]));
            // Writing the same bytes is a no-op — verify by checking
            // the db file mtime doesn't change. Instead, we just
            // confirm commit returns Ok (the skip path returns Ok too).
            lc.commit_state(b"hello").unwrap();
            // Write new bytes and re-read.
            lc.commit_state(b"world").unwrap();
            assert_eq!(lc.restore().as_deref(), Some(&b"world"[..]));
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
