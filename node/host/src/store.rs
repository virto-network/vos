//! The node's storage: one LSM keyspace with four partitions.
//!
//! - `state`: agents' instance rows, keyed by agent, then the agent-relative
//!   key;
//! - `system`: agents' system keys (sessions, reply windows, pair marks,
//!   the outbox), keyed the same way, and the node's applied index per
//!   agent;
//! - `log`: work results by (agent, index), with their term;
//! - `programs`: program blobs by hash.
//!
//! Writes go through a [`Batch`] that both appends log entries and applies
//! work results; the storage thread groups several agents' batches into one
//! commit. One node commits both together, synced. A replicated node
//! appends with a quorum before applying and applies without a sync
//! (section 9.5), with the same two operations.

use std::ops::Bound;
use std::path::Path;

use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode, Readable};
use vos_wire::ids::{AgentId, ProgramHash};
use vos_wire::result::Write;

pub use fjall::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// One replicated log entry: a work result and the term it was proposed in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEntry {
    pub term: u64,
    pub entry: Vec<u8>,
}

/// Whether a commit returns before or after its data reaches the disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Durability {
    /// Handed to the operating system: survives a process crash, not a
    /// power loss.
    Buffered,
    /// Synced to the disk.
    Synced,
}

/// The node's storage.
pub trait Store: Send + Sync {
    type Snapshot: View;
    type Batch: Batch;

    /// A consistent view of every agent's applied state, for refines and
    /// queries.
    fn snapshot(&self) -> Self::Snapshot;

    fn batch(&self) -> Self::Batch;

    fn log_entry(&self, agent: AgentId, index: u64) -> Result<Option<LogEntry>>;

    fn program(&self, hash: &ProgramHash) -> Result<Option<Vec<u8>>>;

    /// Every stored program, for the machine pool at start.
    fn programs(&self) -> Result<Vec<(ProgramHash, Vec<u8>)>>;

    /// The agents this node runs, each with its agent program.
    fn agents(&self) -> Result<Vec<(AgentId, ProgramHash)>>;
}

/// A read-only view of applied state. Keys are relative to the agent.
pub trait View: Send + Sync {
    fn get(&self, agent: AgentId, key: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Rows whose key starts with `prefix`, in key order, starting after
    /// `after` when given. `prefix` must not be empty: it selects the
    /// partition.
    fn scan(
        &self,
        agent: AgentId,
        prefix: &[u8],
        after: Option<&[u8]>,
    ) -> impl Iterator<Item = Result<(Vec<u8>, Vec<u8>)>>;

    /// The last log index applied to the agent's state.
    fn applied(&self, agent: AgentId) -> Result<Option<u64>>;
}

/// An atomic group of writes: all of them or none survive a crash.
pub trait Batch {
    fn append(&mut self, agent: AgentId, index: u64, entry: &LogEntry);

    /// Apply a work result's writes, in order, and record `index` as the
    /// agent's applied index.
    fn apply<'a>(
        &mut self,
        agent: AgentId,
        index: u64,
        writes: impl IntoIterator<Item = &'a Write>,
    );

    fn program(&mut self, hash: &ProgramHash, blob: &[u8]);

    /// Record that this node runs `agent` with the agent program `program`.
    fn agent(&mut self, agent: AgentId, program: &ProgramHash);

    fn commit(self, durability: Durability) -> Result<()>;
}

/// The first byte of an agent-relative system key ([`vos_wire::keys`]).
const SYSTEM: u8 = 0x00;
/// The node's own keys in the `system` partition, after the agent id. No
/// agent key reaches them: only keys starting with [`SYSTEM`] go there.
const NODE: u8 = 0xff;
const APPLIED: u8 = 0x00;
const AGENT: u8 = 0x01;
/// The id no agent gets: node-wide records live under its node keys.
pub const NODE_AGENT: AgentId = AgentId(u32::MAX);

fn agent_key(agent: AgentId, key: &[u8]) -> Vec<u8> {
    [&agent.0.to_be_bytes()[..], key].concat()
}

fn applied_key(agent: AgentId) -> Vec<u8> {
    agent_key(agent, &[NODE, APPLIED])
}

fn registry_prefix() -> Vec<u8> {
    agent_key(NODE_AGENT, &[NODE, AGENT])
}

fn log_key(agent: AgentId, index: u64) -> Vec<u8> {
    agent_key(agent, &index.to_be_bytes())
}

fn encode_entry(entry: &LogEntry) -> Vec<u8> {
    [&entry.term.to_be_bytes()[..], &entry.entry].concat()
}

fn decode_entry(bytes: &[u8]) -> Option<LogEntry> {
    let (term, entry) = bytes.split_first_chunk::<8>()?;
    Some(LogEntry {
        term: u64::from_be_bytes(*term),
        entry: entry.to_vec(),
    })
}

/// Read tuning for the `state` partition. The defaults are the fastest
/// configuration the store benchmark found at 10M rows.
#[derive(Clone, Copy, Debug)]
pub struct Tuning {
    /// Block cache, shared by every partition.
    pub cache_bytes: u64,
    /// Skip filters on the last level, where most rows live: reads of
    /// actor state mostly hit, and a filter that says "maybe" costs a
    /// lookup for nothing. Misses then cost a block search.
    pub expect_hits: bool,
    /// Size of the hash index in each data block, relative to its keys; 0
    /// builds none, and a point read binary-searches the block.
    pub hash_ratio: f32,
    /// Keep every level's filter and index blocks in the cache.
    pub pin_all: bool,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            cache_bytes: 1 << 30,
            expect_hits: true,
            hash_ratio: 0.0,
            pin_all: false,
        }
    }
}

impl Tuning {
    fn rows(&self) -> KeyspaceCreateOptions {
        use fjall::config::{HashRatioPolicy, PinningPolicy};
        let mut options = KeyspaceCreateOptions::default()
            .expect_point_read_hits(self.expect_hits)
            .data_block_hash_ratio_policy(HashRatioPolicy::all(self.hash_ratio));
        if self.pin_all {
            options = options
                .filter_block_pinning_policy(PinningPolicy::all(true))
                .index_block_pinning_policy(PinningPolicy::all(true));
        }
        options
    }
}

/// The fjall-backed store.
#[derive(Clone)]
pub struct Fjall {
    db: Database,
    state: Keyspace,
    system: Keyspace,
    log: Keyspace,
    programs: Keyspace,
}

impl Fjall {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_tuned(path, Tuning::default())
    }

    pub fn open_tuned(path: impl AsRef<Path>, tuning: Tuning) -> Result<Self> {
        let db = Database::builder(path)
            .cache_size(tuning.cache_bytes)
            .open()?;
        Ok(Self {
            state: db.keyspace("state", || tuning.rows())?,
            // System keys are looked up for sessions and replies that are
            // often absent: keep the filters that answer misses cheaply.
            system: db.keyspace("system", KeyspaceCreateOptions::default)?,
            log: db.keyspace("log", KeyspaceCreateOptions::default)?,
            programs: db.keyspace("programs", KeyspaceCreateOptions::default)?,
            db,
        })
    }

    fn partition(&self, key: &[u8]) -> &Keyspace {
        match key.first() {
            Some(&SYSTEM) => &self.system,
            _ => &self.state,
        }
    }

    /// Compact the state partitions into one sorted run each, as after a
    /// bulk load.
    pub fn compact(&self) -> Result<()> {
        self.state.major_compact()?;
        self.system.major_compact()?;
        Ok(())
    }

    pub fn disk_space(&self) -> Result<u64> {
        self.db.disk_space()
    }
}

impl Store for Fjall {
    type Snapshot = FjallSnapshot;
    type Batch = FjallBatch;

    fn snapshot(&self) -> FjallSnapshot {
        FjallSnapshot {
            snapshot: self.db.snapshot(),
            store: self.clone(),
        }
    }

    fn batch(&self) -> FjallBatch {
        FjallBatch {
            batch: self.db.batch(),
            store: self.clone(),
        }
    }

    fn log_entry(&self, agent: AgentId, index: u64) -> Result<Option<LogEntry>> {
        Ok(self
            .log
            .get(log_key(agent, index))?
            .and_then(|bytes| decode_entry(&bytes)))
    }

    fn program(&self, hash: &ProgramHash) -> Result<Option<Vec<u8>>> {
        Ok(self.programs.get(hash.0)?.map(|blob| blob.to_vec()))
    }

    fn programs(&self) -> Result<Vec<(ProgramHash, Vec<u8>)>> {
        self.programs
            .iter()
            .map(|row| {
                let (hash, blob) = row.into_inner()?;
                let hash = hash[..].try_into().expect("a 32-byte program hash");
                Ok((ProgramHash(hash), blob.to_vec()))
            })
            .collect()
    }

    fn agents(&self) -> Result<Vec<(AgentId, ProgramHash)>> {
        let prefix = registry_prefix();
        self.system
            .prefix(&prefix)
            .map(|row| {
                let (key, program) = row.into_inner()?;
                let agent = key[prefix.len()..].try_into().expect("an agent id");
                let program = program[..].try_into().expect("a program hash");
                Ok((AgentId(u32::from_be_bytes(agent)), ProgramHash(program)))
            })
            .collect()
    }
}

pub struct FjallSnapshot {
    snapshot: fjall::Snapshot,
    store: Fjall,
}

impl View for FjallSnapshot {
    fn get(&self, agent: AgentId, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .snapshot
            .get(self.store.partition(key), agent_key(agent, key))?
            .map(|value| value.to_vec()))
    }

    fn scan(
        &self,
        agent: AgentId,
        prefix: &[u8],
        after: Option<&[u8]>,
    ) -> impl Iterator<Item = Result<(Vec<u8>, Vec<u8>)>> {
        assert!(!prefix.is_empty(), "a scan names its partition");
        let start = match after {
            Some(after) if after >= prefix => Bound::Excluded(agent_key(agent, after)),
            _ => Bound::Included(agent_key(agent, prefix)),
        };
        let prefix = agent_key(agent, prefix);
        self.snapshot
            .range(
                self.store.partition(&prefix[4..]),
                (start, Bound::Unbounded),
            )
            .map(|row| row.into_inner())
            .take_while(move |row| match row {
                Ok((key, _)) => key.starts_with(&prefix),
                Err(_) => true,
            })
            .map(|row| {
                let (key, value) = row?;
                Ok((key[4..].to_vec(), value.to_vec()))
            })
    }

    fn applied(&self, agent: AgentId) -> Result<Option<u64>> {
        Ok(self
            .snapshot
            .get(&self.store.system, applied_key(agent))?
            .and_then(|bytes| Some(u64::from_be_bytes(bytes[..].try_into().ok()?))))
    }
}

pub struct FjallBatch {
    batch: fjall::OwnedWriteBatch,
    store: Fjall,
}

impl Batch for FjallBatch {
    fn append(&mut self, agent: AgentId, index: u64, entry: &LogEntry) {
        self.batch
            .insert(&self.store.log, log_key(agent, index), encode_entry(entry));
    }

    fn apply<'a>(
        &mut self,
        agent: AgentId,
        index: u64,
        writes: impl IntoIterator<Item = &'a Write>,
    ) {
        for write in writes {
            let partition = self.store.partition(&write.key);
            let key = agent_key(agent, &write.key);
            match &write.value {
                Some(value) => self.batch.insert(partition, key, value.as_slice()),
                None => self.batch.remove(partition, key),
            }
        }
        self.batch
            .insert(&self.store.system, applied_key(agent), index.to_be_bytes());
    }

    fn program(&mut self, hash: &ProgramHash, blob: &[u8]) {
        self.batch.insert(&self.store.programs, hash.0, blob);
    }

    fn agent(&mut self, agent: AgentId, program: &ProgramHash) {
        let key = [registry_prefix(), agent.0.to_be_bytes().to_vec()].concat();
        self.batch.insert(&self.store.system, key, program.0);
    }

    fn commit(self, durability: Durability) -> Result<()> {
        let mode = match durability {
            Durability::Buffered => PersistMode::Buffer,
            Durability::Synced => PersistMode::SyncAll,
        };
        self.batch.durability(Some(mode)).commit()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vos_wire::ids::{InstanceId, SessionId};
    use vos_wire::keys;

    const A: AgentId = AgentId(1);
    const B: AgentId = AgentId(2);

    fn put(key: Vec<u8>, value: &[u8]) -> Write {
        Write {
            key,
            value: Some(value.to_vec()),
        }
    }

    fn row(instance: u32, index: u64) -> Vec<u8> {
        [
            keys::table_prefix(InstanceId(instance), 7),
            index.to_be_bytes().to_vec(),
        ]
        .concat()
    }

    fn rows(view: &impl View, agent: AgentId, prefix: &[u8], after: Option<&[u8]>) -> Vec<Vec<u8>> {
        view.scan(agent, prefix, after)
            .map(|row| row.unwrap().0)
            .collect()
    }

    #[test]
    fn applies_writes_per_agent_with_their_applied_index() {
        let dir = tempfile::tempdir().unwrap();
        let store = Fjall::open(dir.path()).unwrap();
        let session = keys::session(SessionId(9));
        let mut batch = store.batch();
        batch.apply(
            A,
            1,
            &[put(row(0, 1), b"one"), put(session.clone(), b"mark")],
        );
        batch.apply(B, 4, &[put(row(0, 1), b"other")]);
        batch.commit(Durability::Synced).unwrap();

        let view = store.snapshot();
        assert_eq!(
            view.get(A, &row(0, 1)).unwrap().as_deref(),
            Some(&b"one"[..])
        );
        assert_eq!(
            view.get(B, &row(0, 1)).unwrap().as_deref(),
            Some(&b"other"[..])
        );
        assert_eq!(
            view.get(A, &session).unwrap().as_deref(),
            Some(&b"mark"[..])
        );
        assert_eq!(view.get(B, &session).unwrap(), None);
        assert_eq!(view.applied(A).unwrap(), Some(1));
        assert_eq!(view.applied(B).unwrap(), Some(4));
        assert_eq!(view.applied(AgentId(3)).unwrap(), None);

        let mut batch = store.batch();
        batch.apply(
            A,
            2,
            &[Write {
                key: row(0, 1),
                value: None,
            }],
        );
        batch.commit(Durability::Buffered).unwrap();
        assert_eq!(
            view.get(A, &row(0, 1)).unwrap().as_deref(),
            Some(&b"one"[..]),
            "a snapshot keeps its view"
        );
        assert_eq!(store.snapshot().get(A, &row(0, 1)).unwrap(), None);
        assert_eq!(store.snapshot().applied(A).unwrap(), Some(2));
    }

    #[test]
    fn scans_stay_inside_their_prefix_and_agent() {
        let dir = tempfile::tempdir().unwrap();
        let store = Fjall::open(dir.path()).unwrap();
        let mut batch = store.batch();
        let writes: Vec<_> = (0..5)
            .map(|index| put(row(1, index), b"v"))
            .chain([put(row(0, 9), b"v"), put(row(2, 0), b"v")])
            .collect();
        let mut writes = writes;
        writes.push(put(keys::session(SessionId(1)), b"mark"));
        batch.apply(A, 1, &writes);
        batch.apply(AgentId(0x0100_0000), 1, &[put(row(1, 9), b"v")]);
        batch.apply(B, 1, &[put(row(1, 9), b"v")]);
        batch.commit(Durability::Synced).unwrap();

        let view = store.snapshot();
        let table = keys::table_prefix(InstanceId(1), 7);
        let all: Vec<_> = (0..5).map(|index| row(1, index)).collect();
        assert_eq!(rows(&view, A, &table, None), all);
        assert_eq!(rows(&view, A, &table, Some(&row(1, 2))), all[3..]);
        assert_eq!(
            rows(&view, A, &table, Some(&row(1, 4))),
            Vec::<Vec<u8>>::new()
        );
        assert_eq!(
            rows(&view, A, &table, Some(&row(0, 9))),
            all,
            "a cursor before the prefix starts at the prefix"
        );
        assert_eq!(
            rows(&view, A, &keys::instance_prefix(InstanceId(1)), None),
            all
        );
        assert_eq!(
            rows(&view, A, &[0x00], None),
            vec![keys::session(SessionId(1))],
            "system keys are a partition of their own; the applied index is not an agent key"
        );
        assert_eq!(rows(&view, B, &[0x00], None), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn later_writes_to_a_key_win_within_a_batch() {
        let dir = tempfile::tempdir().unwrap();
        let store = Fjall::open(dir.path()).unwrap();
        let delete = |key: Vec<u8>| Write { key, value: None };
        let mut batch = store.batch();
        batch.apply(
            A,
            1,
            &[
                put(row(0, 1), b"first"),
                put(row(0, 1), b"second"),
                put(row(0, 2), b"gone"),
                delete(row(0, 2)),
                delete(row(0, 3)),
                put(row(0, 3), b"back"),
            ],
        );
        batch.commit(Durability::Buffered).unwrap();
        let view = store.snapshot();
        assert_eq!(
            view.get(A, &row(0, 1)).unwrap().as_deref(),
            Some(&b"second"[..])
        );
        assert_eq!(view.get(A, &row(0, 2)).unwrap(), None);
        assert_eq!(
            view.get(A, &row(0, 3)).unwrap().as_deref(),
            Some(&b"back"[..])
        );
    }

    /// A snapshot sees the applied index and the state rows, which live in
    /// different partitions, as of one commit, while commits continue.
    #[test]
    fn snapshots_agree_across_partitions_under_concurrent_writes() {
        const SLOTS: u64 = 16;
        const RESULTS: u64 = 400;
        let dir = tempfile::tempdir().unwrap();
        let store = Fjall::open(dir.path()).unwrap();
        // Work result i writes i into slots i, i + 1 and i + 2 (mod SLOTS):
        // after result n, slot s holds the last i <= n that wrote it.
        let writes = |index: u64| -> Vec<Write> {
            (0..3)
                .map(|k| put(row(0, (index + k) % SLOTS), &index.to_be_bytes()))
                .collect()
        };
        let expected = |applied: u64, slot: u64| -> Option<u64> {
            (1..=applied)
                .rev()
                .find(|index| (0..3).any(|k| (index + k) % SLOTS == slot))
        };
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for index in 1..=RESULTS {
                    let mut batch = store.batch();
                    batch.apply(A, index, &writes(index));
                    batch.commit(Durability::Buffered).unwrap();
                }
            });
            let mut seen = 0;
            while seen < RESULTS {
                let view = store.snapshot();
                let applied = view.applied(A).unwrap().unwrap_or(0);
                for slot in 0..SLOTS {
                    let value = view
                        .get(A, &row(0, slot))
                        .unwrap()
                        .map(|bytes| u64::from_be_bytes(bytes[..].try_into().unwrap()));
                    assert_eq!(value, expected(applied, slot), "slot {slot} at {applied}");
                }
                assert!(applied >= seen, "a later snapshot never goes back");
                seen = applied;
            }
        });
    }

    /// A flipped bit inside a committed batch is not a torn tail: the store
    /// refuses to open rather than drop or replay it.
    #[test]
    fn a_corrupt_committed_batch_stops_recovery() {
        // Incompressible, so the journal holds it as written.
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let value: Vec<u8> = (0..256)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed as u8
            })
            .collect();
        let dir = tempfile::tempdir().unwrap();
        {
            let store = Fjall::open(dir.path()).unwrap();
            let mut batch = store.batch();
            batch.apply(A, 1, &[put(row(0, 1), &value)]);
            batch.commit(Durability::Synced).unwrap();
        }
        let mut pending = vec![dir.path().to_path_buf()];
        let mut flipped = false;
        while let Some(path) = pending.pop() {
            for entry in std::fs::read_dir(&path).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                if path.extension().is_none_or(|extension| extension != "jnl") {
                    continue;
                }
                let mut bytes = std::fs::read(&path).unwrap();
                if let Some(at) = bytes
                    .windows(value.len())
                    .position(|window| window == value)
                {
                    bytes[at + 100] ^= 0x01;
                    std::fs::write(&path, bytes).unwrap();
                    flipped = true;
                }
            }
        }
        assert!(flipped, "the value is in a journal");
        match Fjall::open(dir.path()) {
            Err(Error::JournalRecovery(fjall::JournalRecoveryError::ChecksumMismatch)) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("opened a store with a corrupt committed batch"),
        }
    }

    #[test]
    fn logs_and_programs_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = Fjall::open(dir.path()).unwrap();
        let entry = LogEntry {
            term: 3,
            entry: b"result".to_vec(),
        };
        let hash = ProgramHash([5; 32]);
        let mut batch = store.batch();
        batch.append(A, 7, &entry);
        batch.program(&hash, b"blob");
        batch.commit(Durability::Synced).unwrap();
        assert_eq!(store.log_entry(A, 7).unwrap(), Some(entry));
        assert_eq!(store.log_entry(A, 8).unwrap(), None);
        assert_eq!(store.log_entry(B, 7).unwrap(), None);
        assert_eq!(store.program(&hash).unwrap().as_deref(), Some(&b"blob"[..]));
        drop(store);

        let reopened = Fjall::open(dir.path()).unwrap();
        assert_eq!(reopened.log_entry(A, 7).unwrap().unwrap().term, 3);
        assert!(reopened.program(&hash).unwrap().is_some());
    }
}
