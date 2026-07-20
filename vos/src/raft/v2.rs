//! Raft log adapter for the JAM-aligned v2 service state machine.
//!
//! Unlike [`super::strategy::RaftCommit`], this adapter never serializes an
//! `EffectLog` and never materializes actor state itself. The replicated data
//! entry is one canonical `AccumulateRequestV2`; `ReplicatedJamServiceV2`
//! executes committed entries through the physical service PVM and advances
//! `last_applied` only after that local service-image commit succeeds.

use alloc::sync::Arc;
use alloc::vec::Vec;
#[cfg(feature = "network")]
use std::sync::mpsc as std_mpsc;
#[cfg(feature = "network")]
use std::time::{Duration, Instant};

use redb::Database;

use crate::commit::CommitError;
use crate::v2::{
    AccumulateRequestV2, CommittedAccumulateBatchV2, CommittedAccumulateEntryV2,
    CommittedAccumulateLogV2, CommittedServiceSnapshotV2, LocalJamStoreSnapshotV2, V2Wire,
};

use super::log::{LogEntry, RaftLog, RaftMeta};
use super::strategy::RaftConfig;
#[cfg(feature = "network")]
use super::worker::{ProposeError, RaftWorker, WorkerHandle};

enum RoleV2 {
    SingleNode,
    #[cfg(feature = "network")]
    Multi {
        worker: RaftWorker,
        apply_rx: std_mpsc::Receiver<u64>,
    },
}

/// Concrete committed-request log used by [`crate::v2::ReplicatedJamServiceV2`].
pub struct RaftAccumulateLogV2 {
    db: Arc<Database>,
    log: RaftLog,
    meta: RaftMeta,
    role: RoleV2,
    cfg: RaftConfig,
}

impl RaftAccumulateLogV2 {
    /// Open a self-quorum log. Every proposal commits in one redb transaction,
    /// but service application and `last_applied` remain a separate ordered
    /// step so restart exercises the same replay contract as a real cluster.
    pub fn open(path: &std::path::Path, cfg: RaftConfig) -> Result<Self, CommitError> {
        let db = Arc::new(Database::create(path)?);
        Self::from_db_arc(db, cfg)
    }

    pub fn from_db_arc(db: Arc<Database>, cfg: RaftConfig) -> Result<Self, CommitError> {
        Ok(Self {
            log: RaftLog::open(db.clone())?,
            meta: RaftMeta::load(&db)?,
            db,
            role: RoleV2::SingleNode,
            cfg,
        })
    }

    /// Attach the canonical-request adapter to a real `vos-raft` worker. The
    /// supplied receiver must be the worker's exclusive commit-index notifier.
    #[cfg(feature = "network")]
    pub fn from_worker(
        db: Arc<Database>,
        cfg: RaftConfig,
        worker: RaftWorker,
        apply_rx: std_mpsc::Receiver<u64>,
    ) -> Result<Self, CommitError> {
        Ok(Self {
            log: RaftLog::open(db.clone())?,
            meta: RaftMeta::load(&db)?,
            db,
            role: RoleV2::Multi { worker, apply_rx },
            cfg,
        })
    }

    #[cfg(feature = "network")]
    pub fn worker_handle(&self) -> Option<WorkerHandle> {
        match &self.role {
            RoleV2::SingleNode => None,
            RoleV2::Multi { worker, .. } => Some(worker.handler()),
        }
    }

    pub fn db(&self) -> &Database {
        &self.db
    }

    pub fn is_writable(&self) -> bool {
        match &self.role {
            RoleV2::SingleNode => true,
            #[cfg(feature = "network")]
            RoleV2::Multi { worker, .. } => worker.role() == super::worker::Role::Leader,
        }
    }

    fn reload(&mut self) -> Result<(), CommitError> {
        self.meta = RaftMeta::load(&self.db)?;
        self.log = RaftLog::open(self.db.clone())?;
        Ok(())
    }

    fn validate_request(bytes: &[u8]) -> Result<(), CommitError> {
        AccumulateRequestV2::decode(bytes).map(|_| ()).map_err(|_| {
            CommitError::Config("raft v2 entry is not a canonical AccumulateRequestV2".into())
        })
    }

    fn decode_entry(entry: LogEntry) -> Result<Option<CommittedAccumulateEntryV2>, CommitError> {
        match super::redb_storage::decode_entry_kind(&entry.payload)? {
            vos_raft::EntryKind::Data { payload } if payload.is_empty() => Ok(None),
            vos_raft::EntryKind::Data { payload } => {
                Self::validate_request(&payload)?;
                Ok(Some(CommittedAccumulateEntryV2 {
                    index: entry.index,
                    request: payload,
                }))
            }
            vos_raft::EntryKind::ConfigChange { .. } => Ok(None),
            _ => Ok(None),
        }
    }

    fn committed_entry(&mut self, index: u64) -> Result<CommittedAccumulateEntryV2, CommitError> {
        self.reload()?;
        if index > self.meta.commit_index || index <= self.meta.snap_last_index {
            return Err(CommitError::Config(alloc::format!(
                "raft v2 proposal index {index} is not available at committed index {}",
                self.meta.commit_index,
            )));
        }
        let mut entries = self.log.entries(index, index)?;
        let entry = entries.pop().ok_or_else(|| {
            CommitError::Config(alloc::format!("raft v2 committed entry {index} is missing"))
        })?;
        Self::decode_entry(entry)?.ok_or_else(|| {
            CommitError::Config(alloc::format!(
                "raft v2 proposal index {index} is not an application entry"
            ))
        })
    }

    fn propose_single(
        &mut self,
        request: &[u8],
    ) -> Result<CommittedAccumulateEntryV2, CommitError> {
        let cache = self.log.cache_snapshot();
        let result: Result<CommittedAccumulateEntryV2, CommitError> = (|| {
            let transaction = self.db.begin_write()?;
            let kind = vos_raft::EntryKind::Data {
                payload: request.to_vec(),
            };
            let on_disk = super::redb_storage::encode_entry_kind(&kind);
            let index = self
                .log
                .append_in_txn(&transaction, self.meta.current_term, &on_disk)?;
            self.meta.commit_index = index;
            self.meta.write_in_txn(&transaction)?;
            transaction.commit()?;
            Ok(CommittedAccumulateEntryV2 {
                index,
                request: request.to_vec(),
            })
        })();
        if let Err(error) = result {
            self.log.cache_restore(cache);
            if let Ok(meta) = RaftMeta::load(&self.db) {
                self.meta = meta;
            }
            return Err(error);
        }
        result
    }

    #[cfg(feature = "network")]
    fn propose_multi(&mut self, request: &[u8]) -> Result<CommittedAccumulateEntryV2, CommitError> {
        let RoleV2::Multi { worker, apply_rx } = &self.role else {
            unreachable!()
        };
        let index = worker
            .handler()
            .propose(request.to_vec())
            .map_err(|error| match error {
                ProposeError::NotLeader => {
                    CommitError::Config("raft v2 proposal reached a non-leader replica".into())
                }
                ProposeError::Storage(error) => error,
            })?;
        let timeout = Duration::from_millis(self.cfg.propose_timeout_ms);
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(CommitError::Config(alloc::format!(
                    "raft v2 proposal at index {index} did not reach quorum within {} ms",
                    self.cfg.propose_timeout_ms,
                )));
            }
            match apply_rx.recv_timeout(remaining) {
                Ok(committed) if committed >= index => break,
                Ok(_) => continue,
                Err(std_mpsc::RecvTimeoutError::Timeout) => {
                    return Err(CommitError::Config(alloc::format!(
                        "raft v2 timeout waiting for committed index {index}"
                    )));
                }
                Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(CommitError::Config(
                        "raft v2 worker commit-index channel closed".into(),
                    ));
                }
            }
        }
        let entry = self.committed_entry(index)?;
        if entry.request != request {
            return Err(CommitError::Config(alloc::format!(
                "raft v2 committed bytes at proposal index {index} changed"
            )));
        }
        Ok(entry)
    }
}

impl CommittedAccumulateLogV2 for RaftAccumulateLogV2 {
    type Error = CommitError;

    fn propose(&mut self, request: &[u8]) -> Result<CommittedAccumulateEntryV2, Self::Error> {
        Self::validate_request(request)?;
        match &self.role {
            RoleV2::SingleNode => self.propose_single(request),
            #[cfg(feature = "network")]
            RoleV2::Multi { .. } => self.propose_multi(request),
        }
    }

    fn committed_after(
        &mut self,
        applied_index: u64,
    ) -> Result<CommittedAccumulateBatchV2, Self::Error> {
        self.reload()?;
        if applied_index != self.meta.last_applied || applied_index > self.meta.commit_index {
            return Err(CommitError::Config(alloc::format!(
                "raft v2 apply cursor mismatch: requested {applied_index}, durable {}, committed {}",
                self.meta.last_applied,
                self.meta.commit_index,
            )));
        }
        if applied_index < self.meta.snap_last_index {
            return Err(CommitError::Config(alloc::format!(
                "raft v2 service image is behind compacted index {}; install a service snapshot before replay",
                self.meta.snap_last_index,
            )));
        }
        let mut entries = Vec::new();
        for entry in self
            .log
            .entries(applied_index.saturating_add(1), self.meta.commit_index)?
        {
            if let Some(entry) = Self::decode_entry(entry)? {
                entries.push(entry);
            }
        }
        Ok(CommittedAccumulateBatchV2 {
            entries,
            committed_index: self.meta.commit_index,
        })
    }

    fn applied_index(&mut self) -> Result<u64, Self::Error> {
        self.reload()?;
        Ok(self.meta.last_applied)
    }

    fn installed_snapshot_after(
        &mut self,
        applied_index: u64,
    ) -> Result<Option<CommittedServiceSnapshotV2>, Self::Error> {
        self.reload()?;
        if applied_index != self.meta.last_applied {
            return Err(CommitError::Config(alloc::format!(
                "raft v2 snapshot cursor mismatch: requested {applied_index}, durable {}",
                self.meta.last_applied,
            )));
        }
        if applied_index >= self.meta.snap_last_index {
            return Ok(None);
        }
        let bytes = super::redb_storage::read_state_bytes(&self.db)?;
        let snapshot = CommittedServiceSnapshotV2::decode(&bytes).map_err(|_| {
            CommitError::Config("raft v2 installed service snapshot is not canonical".into())
        })?;
        if snapshot.applied_index != self.meta.snap_last_index {
            return Err(CommitError::Config(alloc::format!(
                "raft v2 snapshot image index {} does not match installed index {}",
                snapshot.applied_index,
                self.meta.snap_last_index,
            )));
        }
        Ok(Some(snapshot))
    }

    fn mark_applied(&mut self, index: u64, service_image: &[u8]) -> Result<(), Self::Error> {
        self.meta = RaftMeta::load(&self.db)?;
        if index < self.meta.last_applied || index > self.meta.commit_index {
            return Err(CommitError::Config(alloc::format!(
                "raft v2 cannot advance applied index from {} to {index} with committed index {}",
                self.meta.last_applied,
                self.meta.commit_index,
            )));
        }
        LocalJamStoreSnapshotV2::decode(service_image).map_err(|_| {
            CommitError::Config("raft v2 applied service image is not canonical".into())
        })?;
        let snapshot = CommittedServiceSnapshotV2 {
            applied_index: index,
            service_image: service_image.to_vec(),
        }
        .encode();
        let transaction = self.db.begin_write()?;
        super::redb_storage::write_applied_state_v2_in_txn(&transaction, index, &snapshot)?;
        self.meta.last_applied = index;
        self.meta.write_host_fields_in_txn(&transaction)?;
        transaction.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::redb_storage::RedbStorage;
    use super::*;
    use crate::v2::{
        ABI_VERSION, DeploymentId, EXECUTION_SEMANTICS_ID, Hash, InvocationId, ProgramId,
        PublicationAckV2, RootServiceId, ServiceIdentityV2, SpaceId, WorkInputIdV2,
    };
    use vos_raft::{Meta, Storage, WriteBatch};

    fn request(byte: u8) -> AccumulateRequestV2 {
        AccumulateRequestV2::AcknowledgePublication(PublicationAckV2 {
            service: ServiceIdentityV2 {
                space: SpaceId([byte; 32]),
                root_service: RootServiceId([2; 32]),
                deployment: DeploymentId([3; 32]),
                service_program: ProgramId([4; 32]),
                service_abi: ABI_VERSION,
                execution_semantics: EXECUTION_SEMANTICS_ID,
            },
            input: WorkInputIdV2 {
                invocation: InvocationId([5; 32]),
                workflow_step: 6,
            },
            publication: Hash([7; 32]),
        })
    }

    fn temp_path() -> (std::path::PathBuf, std::path::PathBuf) {
        let directory = std::env::temp_dir().join(alloc::format!(
            "vos-raft-v2-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&directory).unwrap();
        (directory.join("raft.redb"), directory)
    }

    fn service_image(byte: u8) -> Vec<u8> {
        let mut store = crate::v2::LocalJamStoreV2::default();
        store.import_blob(vec![byte]);
        store.snapshot_bytes()
    }

    #[test]
    fn single_node_log_recovers_canonical_requests_and_apply_cursor() {
        let (path, directory) = temp_path();
        let mut log = RaftAccumulateLogV2::open(&path, RaftConfig::default()).unwrap();
        let bytes = request(1).encode();
        let committed = log.propose(&bytes).unwrap();
        assert_eq!(committed.index, 1);
        assert_eq!(log.applied_index().unwrap(), 0);
        assert_eq!(
            log.committed_after(0).unwrap(),
            CommittedAccumulateBatchV2 {
                entries: vec![committed],
                committed_index: 1,
            }
        );
        let service_image = LocalJamStoreSnapshotV2::default().encode();
        log.mark_applied(1, &service_image).unwrap();
        drop(log);

        let mut restarted = RaftAccumulateLogV2::open(&path, RaftConfig::default()).unwrap();
        assert_eq!(restarted.applied_index().unwrap(), 1);
        assert_eq!(
            restarted.committed_after(1).unwrap(),
            CommittedAccumulateBatchV2 {
                entries: vec![],
                committed_index: 1,
            }
        );
        assert!(restarted.propose(b"not a v2 request").is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn compaction_freezes_the_exact_applied_service_image() {
        let (path, directory) = temp_path();
        let db = Arc::new(Database::create(&path).unwrap());
        let mut log = RaftAccumulateLogV2::from_db_arc(db.clone(), RaftConfig::default()).unwrap();
        let first = log.propose(&request(1).encode()).unwrap();
        let first_image = service_image(1);
        log.mark_applied(first.index, &first_image).unwrap();
        let second = log.propose(&request(2).encode()).unwrap();
        let second_image = service_image(2);
        log.mark_applied(second.index, &second_image).unwrap();
        drop(log);

        let mut storage = RedbStorage::open(db).unwrap();
        futures_executor::block_on(storage.commit_batch(WriteBatch {
            compact_to: Some((first.index, 0)),
            ..Default::default()
        }))
        .unwrap();
        let frozen = CommittedServiceSnapshotV2::decode(
            &futures_executor::block_on(storage.read_state()).unwrap(),
        )
        .unwrap();
        assert_eq!(frozen.applied_index, first.index);
        assert_eq!(frozen.service_image, first_image);

        futures_executor::block_on(storage.commit_batch(WriteBatch {
            compact_to: Some((second.index, 0)),
            ..Default::default()
        }))
        .unwrap();
        let frozen = CommittedServiceSnapshotV2::decode(
            &futures_executor::block_on(storage.read_state()).unwrap(),
        )
        .unwrap();
        assert_eq!(frozen.applied_index, second.index);
        assert_eq!(frozen.service_image, second_image);
        drop(storage);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn installed_snapshot_is_exposed_until_its_service_image_is_applied() {
        let (path, directory) = temp_path();
        let db = Arc::new(Database::create(&path).unwrap());
        let service_image = service_image(3);
        let snapshot = CommittedServiceSnapshotV2 {
            applied_index: 4,
            service_image: service_image.clone(),
        };
        let mut storage = RedbStorage::open(db.clone()).unwrap();
        futures_executor::block_on(storage.commit_batch(WriteBatch {
            compact_to: Some((4, 2)),
            state: Some(snapshot.encode()),
            meta: Some(Meta {
                current_term: 2,
                voted_for: None,
                commit_index: 4,
                snap_last_index: 4,
                snap_last_term: 2,
            }),
            ..Default::default()
        }))
        .unwrap();
        drop(storage);

        let mut log = RaftAccumulateLogV2::from_db_arc(db, RaftConfig::default()).unwrap();
        assert_eq!(log.applied_index().unwrap(), 0);
        assert_eq!(log.installed_snapshot_after(0).unwrap(), Some(snapshot));
        log.mark_applied(4, &service_image).unwrap();
        assert_eq!(log.applied_index().unwrap(), 4);
        assert_eq!(log.installed_snapshot_after(4).unwrap(), None);
        drop(log);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(feature = "network")]
    #[test]
    fn worker_backed_log_waits_for_quorum_before_exposing_request() {
        use super::super::worker::{RaftWorker, Role, WorkerConfig};

        let (path, directory) = temp_path();
        let db = Arc::new(Database::create(&path).unwrap());
        let cfg = RaftConfig {
            me: 0xA11C,
            members: vec![0xA11C],
            election_timeout_ms: (10, 30),
            heartbeat_interval_ms: 5,
            replication_id: [0xA1; 32],
            propose_timeout_ms: 2_000,
        };
        let (apply_tx, apply_rx) = std_mpsc::channel::<u64>();
        let worker = RaftWorker::spawn(
            db.clone(),
            WorkerConfig {
                me: cfg.me,
                members: cfg.members.clone(),
                replication_id: cfg.replication_id,
                election_timeout_ms: cfg.election_timeout_ms,
                heartbeat_interval_ms: cfg.heartbeat_interval_ms,
            },
            None,
            Some(apply_tx),
        );

        let handle = worker.handler();
        let deadline = Instant::now() + Duration::from_secs(5);
        while handle
            .snapshot()
            .is_none_or(|snapshot| snapshot.role != Role::Leader)
        {
            assert!(
                Instant::now() < deadline,
                "single-member cluster did not elect"
            );
            std::thread::sleep(Duration::from_millis(5));
        }

        let mut log = RaftAccumulateLogV2::from_worker(db, cfg, worker, apply_rx).unwrap();
        let bytes = request(2).encode();
        let committed = log.propose(&bytes).unwrap();

        // Index 1 is the leader's current-term no-op. The canonical request
        // follows it and is visible only after the worker reports quorum.
        assert_eq!(committed.index, 2);
        assert_eq!(committed.request, bytes);
        assert_eq!(log.applied_index().unwrap(), 0);
        assert_eq!(
            log.committed_after(0).unwrap(),
            CommittedAccumulateBatchV2 {
                entries: vec![committed],
                committed_index: 2,
            }
        );
        let service_image = LocalJamStoreSnapshotV2::default().encode();
        log.mark_applied(2, &service_image).unwrap();
        assert_eq!(log.applied_index().unwrap(), 2);

        drop(log);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
