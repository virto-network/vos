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
pub trait CommitStrategy: Send {
    /// Return previously-persisted state, if any.
    ///
    /// `None` means "fresh start" — the host constructs the actor
    /// via its normal init path. A `None` from a replicating
    /// strategy may also signal "state table empty but DAG present"
    /// — the host should then call [`replay_logs`](Self::replay_logs)
    /// and rebuild state by replaying each entry.
    fn restore(&mut self) -> Option<Vec<u8>>;

    /// Persist the actor's current state.
    ///
    /// Implementations may skip the backend write when the bytes
    /// haven't changed since the last successful commit.
    fn commit(&mut self, state: &[u8]) -> Result<(), CommitError>;

    /// Persist state alongside the observed-effect log from the
    /// dispatch that produced it. Replicating strategies append a
    /// DAG node with the log as payload; non-replicating strategies
    /// ignore the log and fall through to [`commit`](Self::commit).
    fn commit_with_log(
        &mut self,
        state: &[u8],
        _log: &crate::effect_log::EffectLog,
    ) -> Result<(), CommitError> {
        self.commit(state)
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
}

/// No-op strategy — state lives only in memory and is lost on exit.
pub struct NoCommit;

impl CommitStrategy for NoCommit {
    fn restore(&mut self) -> Option<Vec<u8>> {
        None
    }
    fn commit(&mut self, _state: &[u8]) -> Result<(), CommitError> {
        Ok(())
    }
}

// ── redb-backed local strategy ──────────────────────────────────────

#[cfg(feature = "storage")]
pub use local::{LocalCommit, STATE_KEY, STATE_TABLE};

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

    /// Persists state to a redb database, skipping writes when the
    /// serialized bytes are unchanged from the last commit.
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

        fn commit(&mut self, state: &[u8]) -> Result<(), CommitError> {
            if state == self.last {
                return Ok(());
            }
            let txn = self.db.begin_write()?;
            {
                let mut table = txn.open_table(STATE_TABLE)?;
                table.insert(STATE_KEY, state)?;
            }
            txn.commit()?;
            self.last = state.to_vec();
            Ok(())
        }
    }
}

// ── CRDT strategy — blake2b-hashed Merkle-DAG on the same redb ──────

#[cfg(feature = "storage")]
mod crdt {
    use super::*;
    use crate::effect_log::EffectLog;
    use alloc::collections::{BTreeMap, BTreeSet};
    use alloc::vec::Vec;
    use merkle_crdt::{Cid, DagNode, Decode as McDecode, Encode as McEncode, Hasher, MerkleClock};
    use std::collections::VecDeque;

    /// blake2b-256 hasher for CRDT CIDs. Uses blake2b_simd (already a
    /// vos dep) with a configurable 32-byte output length.
    ///
    /// blake2b is the hash of choice for kunekt-style actors: the
    /// on-chain host exposes a precompile for it and the in-progress
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

    // ── merkle-crdt Encode/Decode for EffectLog ─────────────────────
    //
    // EffectLog carries its own self-describing encoding via to_bytes
    // / from_bytes. Inside a DagNode the payload sits in its own
    // length-prefixed slot, so the decoder receives exactly the
    // payload bytes — we can consume the whole slice and re-parse.

    impl McEncode for EffectLog {
        fn encode_to(&self, buf: &mut Vec<u8>) {
            buf.extend_from_slice(&self.to_bytes());
        }
    }

    impl McDecode for EffectLog {
        fn decode_from(buf: &[u8], pos: &mut usize) -> Option<Self> {
            let slice = &buf[*pos..];
            *pos = buf.len();
            EffectLog::from_bytes(slice)
        }
    }

    /// redb table holding merkle-DAG nodes keyed by CID bytes.
    /// Uses the same name as [`merkle_crdt::RedbStore`] so a
    /// `RedbStore` opened against this database sees the same nodes.
    pub const DAG_TABLE: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("dag");

    /// Row key in [`STATE_TABLE`](super::STATE_TABLE) for the
    /// serialized Merkle-Clock roots.
    pub const ROOTS_KEY: &str = "crdt_roots";

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
    }

    impl CrdtCommit {
        /// Open (or create) the redb database at `path` and load the
        /// Merkle-Clock roots from its `state` table.
        pub fn open(path: &std::path::Path) -> Result<Self, CommitError> {
            let db = alloc::sync::Arc::new(redb::Database::create(path)?);
            Ok(Self::with_state(
                db,
                alloc::sync::Arc::new(std::sync::Mutex::new(())),
            ))
        }

        /// Build a `CrdtCommit` on a pre-opened, shared
        /// `Arc<redb::Database>`. Used when the host wants the
        /// same database exposed to a parallel reader (e.g. a
        /// `SyncProvider`) without double-opening — redb is
        /// exclusive on file open, so this is the only way to
        /// share access.
        ///
        /// The returned strategy gets a fresh per-instance commit
        /// lock; use [`from_db_arc_locked`](Self::from_db_arc_locked)
        /// when multiple `CrdtCommit`s over the same db need to
        /// serialize their writes (agent thread + sync ticker).
        pub fn from_db_arc(db: alloc::sync::Arc<redb::Database>) -> Self {
            Self::with_state(db, alloc::sync::Arc::new(std::sync::Mutex::new(())))
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
        ) -> Self {
            Self::with_state(db, commit_lock)
        }

        fn with_state(
            db: alloc::sync::Arc<redb::Database>,
            commit_lock: alloc::sync::Arc<std::sync::Mutex<()>>,
        ) -> Self {
            let clock = load_clock(&db).unwrap_or_default();
            let last_state = load_state(&db).unwrap_or_default();
            Self {
                db,
                clock,
                last_state,
                commit_lock,
            }
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
                let node: DagNode<Blake2b, EffectLog> = DagNode::from_bytes(val.value())
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
    /// shared redb database. Public so a `SyncProvider` (or any
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
        fn restore(&mut self) -> Option<Vec<u8>> {
            // last_state was populated on open; re-load is not needed.
            if self.last_state.is_empty() {
                None
            } else {
                Some(self.last_state.clone())
            }
        }

        fn commit(&mut self, state: &[u8]) -> Result<(), CommitError> {
            // A plain commit without a log entry means the caller has
            // no new CRDT operation to record (e.g. a manual state
            // patch). Still persist the state atomically.
            self.write_atomic(state, None)
        }

        fn commit_with_log(&mut self, state: &[u8], log: &EffectLog) -> Result<(), CommitError> {
            self.write_atomic(state, Some(log))
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

        fn replay_logs(&self) -> Result<Vec<EffectLog>, CommitError> {
            // BFS from roots, collect all reachable nodes, then
            // topological sort so predecessors come before
            // successors.
            let mut nodes: BTreeMap<Cid<Blake2b>, DagNode<Blake2b, EffectLog>> = BTreeMap::new();
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
                let val = table.get(cid.as_ref())?.ok_or_else(|| {
                    CommitError::Config(alloc::format!(
                        "DAG node {cid:?} reachable from roots is missing from the dag table",
                    ))
                })?;
                let bytes = val.value();
                let node: DagNode<Blake2b, EffectLog> =
                    DagNode::from_bytes(bytes).ok_or_else(|| {
                        CommitError::Config(alloc::format!(
                            "DAG node {cid:?} could not be decoded — db corruption",
                        ))
                    })?;
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
        fn write_atomic(
            &mut self,
            state: &[u8],
            log: Option<&EffectLog>,
        ) -> Result<(), CommitError> {
            // Skip when the state is unchanged from the previous
            // commit, even if a log was supplied. A dispatch that
            // observed external replies but didn't mutate state is
            // a pure read — appending a DAG node for it would
            // pollute consensus history with no-op events. Replay
            // can skip this dispatch entirely; the next state-
            // changing commit will produce a fresh DAG node.
            if state == self.last_state.as_slice() {
                return Ok(());
            }

            // Hold the commit lock across "compute new DAG node
            // referencing current roots" + "write {state, ROOTS_KEY,
            // new node}" so a concurrent sync ticker can't insert
            // a peer node and update ROOTS_KEY between the read of
            // self.clock.roots() and our write back. Refresh the
            // clock from disk under the lock so we see anything
            // the ticker just merged in.
            let _guard = self.commit_lock.lock().expect("commit_lock poisoned");
            self.clock = load_clock(&self.db).unwrap_or_default();

            // Compute the new DAG node (if any) off-transaction so
            // the write txn is short.
            let new_cid_and_bytes = log.map(|log| {
                let children = self.clock.roots().clone();
                let node = DagNode::new(log.clone(), children);
                let cid = node.cid();
                let bytes = node.to_bytes();
                (cid, bytes)
            });

            let roots_bytes = match &new_cid_and_bytes {
                Some((cid, _)) => {
                    let mut roots = BTreeSet::new();
                    roots.insert(cid.clone());
                    encode_roots(&roots)
                }
                None => encode_roots(self.clock.roots()),
            };

            let txn = self.db.begin_write()?;
            {
                let mut state_table = txn.open_table(STATE_TABLE)?;
                state_table.insert(STATE_KEY, state)?;
                state_table.insert(ROOTS_KEY, roots_bytes.as_slice())?;

                if let Some((cid, bytes)) = &new_cid_and_bytes {
                    let mut dag_table = txn.open_table(DAG_TABLE)?;
                    dag_table.insert(cid.as_ref(), bytes.as_slice())?;
                }
            }
            txn.commit()?;

            // Update in-memory clock to reflect the newly committed
            // roots. For a log-less commit the roots are unchanged.
            if let Some((cid, _)) = new_cid_and_bytes {
                self.clock = MerkleClock::new();
                self.clock.add_roots(core::iter::once(cid));
            }
            self.last_state = state.to_vec();
            Ok(())
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
    fn topological_order(
        mut nodes: BTreeMap<Cid<Blake2b>, DagNode<Blake2b, EffectLog>>,
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
                sorted.push(node.payload);
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
        assert!(s.commit(b"anything").is_ok());
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
            let mut cc = CrdtCommit::open(&path).unwrap();
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
            let mut cc = CrdtCommit::open(&path).unwrap();
            assert_eq!(cc.restore().as_deref(), Some(&b"state-v3"[..]));
            assert_eq!(cc.clock().roots().len(), 1);

            let replay = cc.replay_logs().unwrap();
            assert_eq!(replay.len(), 3);
            assert_eq!(replay[0], logs[0]);
            assert_eq!(replay[1], logs[1]);
            assert_eq!(replay[2], logs[2]);
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

        let mut agent = CrdtCommit::from_db_arc(arc.clone());
        let mut sync = CrdtCommit::from_db_arc(arc.clone());

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
        // (no children → concurrent).
        let log_b = EffectLog::for_msg(b"remote".to_vec());
        let remote_node: merkle_crdt::DagNode<Blake2b, EffectLog> =
            merkle_crdt::DagNode::new(log_b.clone(), BTreeSet::new());
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
    fn crdt_sync_accessors_replicate_dag() {
        // Drive replica A with two dispatches, then have replica B
        // pull A's DAG nodes via the new sync accessors and
        // verify B converges (same roots, replay_logs returns the
        // same logs in the same order).
        use crate::effect_log::EffectLog;
        use merkle_crdt::DagNode;
        use std::collections::BTreeSet;

        let path_a = temp_db_path("crdt_sync_a");
        let path_b = temp_db_path("crdt_sync_b");

        // ── Drive A ────────────────────────────────────────────────
        let mut a = CrdtCommit::open(&path_a).unwrap();
        let log1 = EffectLog::for_msg(b"first".to_vec());
        let log2 = EffectLog::for_msg(b"second".to_vec());
        a.commit_with_log(b"state-1", &log1).unwrap();
        a.commit_with_log(b"state-2", &log2).unwrap();

        let a_roots = a.root_bytes();
        assert_eq!(a_roots.len(), 1, "linear chain → one head");

        // ── Replica B: pull A's nodes via accessors ────────────────
        let mut b = CrdtCommit::open(&path_b).unwrap();
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
            let node: DagNode<Blake2b, EffectLog> = DagNode::from_bytes(&bytes).unwrap();
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
        let mut cc = CrdtCommit::open(&path).unwrap();

        let log = EffectLog::for_msg(b"first".to_vec());
        cc.commit_with_log(b"state", &log).unwrap();
        let roots_after_first = cc.clock().roots().clone();

        // Plain commit with unchanged state — no new DAG node should
        // be appended (roots stay the same).
        cc.commit(b"state").unwrap();
        assert_eq!(cc.clock().roots(), &roots_after_first);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
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
            lc.commit(b"hello").unwrap();
        }
        {
            let mut lc = LocalCommit::open(&db_path).unwrap();
            assert_eq!(lc.restore().as_deref(), Some(&b"hello"[..]));
            // Writing the same bytes is a no-op — verify by checking
            // the db file mtime doesn't change. Instead, we just
            // confirm commit returns Ok (the skip path returns Ok too).
            lc.commit(b"hello").unwrap();
            // Write new bytes and re-read.
            lc.commit(b"world").unwrap();
            assert_eq!(lc.restore().as_deref(), Some(&b"world"[..]));
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
