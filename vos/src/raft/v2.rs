//! Raft log adapter for the JAM-aligned v2 service state machine.
//!
//! Unlike [`super::strategy::RaftCommit`], this adapter never serializes an
//! `EffectLog` and never materializes actor state itself. The replicated data
//! entry carries one canonical `AccumulateRequestV2` plus the authenticated
//! JAM slot for time-dependent requests; `ReplicatedJamServiceV2` executes
//! committed entries through the physical service PVM and advances
//! `last_applied` only after that local service-image commit succeeds.

use alloc::sync::Arc;
use alloc::vec::Vec;
#[cfg(feature = "network")]
use std::sync::mpsc as std_mpsc;
#[cfg(feature = "network")]
use std::time::{Duration, Instant};

use redb::Database;

use crate::commit::CommitError;
use crate::v2::wire::{DecodeError, Decoder, Encoder};
use crate::v2::{
    AccumulateRequestV2, CommittedAccumulateBatchV2, CommittedAccumulateEntryV2,
    CommittedAccumulateLogV2, CommittedServiceSnapshotV2, ImportedBlobV2, LocalJamStoreSnapshotV2,
    V2Wire,
};

use super::log::{LogEntry, RaftLog, RaftMeta};
use super::strategy::RaftConfig;
#[cfg(feature = "network")]
use super::worker::{ProposeError, RaftWorker, ReadIndexError, WorkerHandle};

#[derive(Debug, Clone, PartialEq, Eq)]
struct RaftAccumulatePayloadV2 {
    request: Vec<u8>,
    logical_timeslot: Option<u64>,
}

impl RaftAccumulatePayloadV2 {
    fn from_request(request: &[u8], logical_timeslot: Option<u64>) -> Result<Self, CommitError> {
        let decoded = AccumulateRequestV2::decode(request).map_err(|_| {
            CommitError::Config("raft v2 entry is not a canonical AccumulateRequestV2".into())
        })?;
        if matches!(decoded, AccumulateRequestV2::ExpireCall(_)) != logical_timeslot.is_some() {
            return Err(CommitError::Config(
                "raft v2 time-dependent entry has invalid JAM-slot provenance".into(),
            ));
        }
        Ok(Self {
            request: request.to_vec(),
            logical_timeslot,
        })
    }
}

impl V2Wire for RaftAccumulatePayloadV2 {
    const MAGIC: [u8; 4] = *b"VRQ2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut encoder = Encoder(out);
        encoder.bytes(&self.request);
        encoder.option(&self.logical_timeslot, |encoder, slot| encoder.u64(*slot));
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let request = decoder.bytes()?;
        let logical_timeslot = decoder.option(Decoder::u64)?;
        let decoded =
            AccumulateRequestV2::decode(&request).map_err(|_| DecodeError::NonCanonical)?;
        if matches!(decoded, AccumulateRequestV2::ExpireCall(_)) != logical_timeslot.is_some() {
            return Err(DecodeError::NonCanonical);
        }
        Ok(Self {
            request,
            logical_timeslot,
        })
    }
}

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
    /// Stable identity of the replication group backing this request log.
    pub const fn replication_id(&self) -> [u8; 32] {
        self.cfg.replication_id
    }

    /// Operator-configured bound shared by the read barrier and each proposal
    /// wait. Node ingress uses it to derive one encompassing typed-call
    /// deadline instead of imposing a shorter unrelated host timeout.
    pub(crate) const fn propose_timeout_ms(&self) -> u64 {
        self.cfg.propose_timeout_ms
    }

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

    fn decode_payload(bytes: &[u8]) -> Result<RaftAccumulatePayloadV2, CommitError> {
        RaftAccumulatePayloadV2::decode(bytes).map_err(|_| {
            CommitError::Config("raft v2 entry is not a canonical replicated request".into())
        })
    }

    fn decode_entry(entry: LogEntry) -> Result<Option<CommittedAccumulateEntryV2>, CommitError> {
        match super::redb_storage::decode_entry_kind(&entry.payload)? {
            vos_raft::EntryKind::Data { payload } if payload.is_empty() => Ok(None),
            vos_raft::EntryKind::Data { payload } => {
                let payload = Self::decode_payload(&payload)?;
                Ok(Some(CommittedAccumulateEntryV2 {
                    index: entry.index,
                    request: payload.request,
                    logical_timeslot: payload.logical_timeslot,
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
        payload: &[u8],
    ) -> Result<CommittedAccumulateEntryV2, CommitError> {
        let decoded = Self::decode_payload(payload)?;
        let cache = self.log.cache_snapshot();
        let result: Result<CommittedAccumulateEntryV2, CommitError> = (|| {
            let transaction = self.db.begin_write()?;
            let kind = vos_raft::EntryKind::Data {
                payload: payload.to_vec(),
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
                request: decoded.request,
                logical_timeslot: decoded.logical_timeslot,
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
    fn propose_multi(&mut self, payload: &[u8]) -> Result<CommittedAccumulateEntryV2, CommitError> {
        let decoded = Self::decode_payload(payload)?;
        let RoleV2::Multi { worker, apply_rx } = &self.role else {
            unreachable!()
        };
        let index = worker
            .handler()
            .propose(payload.to_vec())
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
        if entry.request != decoded.request || entry.logical_timeslot != decoded.logical_timeslot {
            return Err(CommitError::Config(alloc::format!(
                "raft v2 committed bytes at proposal index {index} changed"
            )));
        }
        Ok(entry)
    }
}

impl CommittedAccumulateLogV2 for RaftAccumulateLogV2 {
    type Error = CommitError;

    fn leader_read_index(&mut self) -> Result<u64, Self::Error> {
        match &self.role {
            RoleV2::SingleNode => {
                self.reload()?;
                Ok(self.meta.commit_index)
            }
            #[cfg(feature = "network")]
            // Admission and proposal share one operator-visible liveness
            // budget. The worker owns this deadline and removes the pending
            // read on expiry, so an isolated leader cannot strand the root's
            // sole service thread or leak read-barrier queue slots.
            RoleV2::Multi { worker, .. } => worker
                .handler()
                .read_index(Duration::from_millis(self.cfg.propose_timeout_ms))
                .map_err(|error| {
                    let reason = match error {
                        ReadIndexError::NotLeader => "not leader",
                        ReadIndexError::LeaderStepped => "leader stepped down",
                        ReadIndexError::Backpressure => "backpressure",
                        ReadIndexError::TimedOut => "timed out",
                    };
                    CommitError::Config(alloc::format!(
                        "raft v2 current-term read barrier failed: {reason}"
                    ))
                }),
        }
    }

    fn propose_at(
        &mut self,
        request: &[u8],
        logical_timeslot: Option<u64>,
    ) -> Result<CommittedAccumulateEntryV2, Self::Error> {
        let payload = RaftAccumulatePayloadV2::from_request(request, logical_timeslot)?.encode();
        match &self.role {
            RoleV2::SingleNode => self.propose_single(&payload),
            #[cfg(feature = "network")]
            RoleV2::Multi { .. } => self.propose_multi(&payload),
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

    fn mark_applied(
        &mut self,
        index: u64,
        service_image: &[u8],
        proof_artifacts: &[ImportedBlobV2],
    ) -> Result<(), Self::Error> {
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
            proof_artifacts: proof_artifacts.to_vec(),
        }
        .encode();
        CommittedServiceSnapshotV2::decode(&snapshot).map_err(|_| {
            CommitError::Config(
                "raft v2 applied service image exceeds the committed snapshot wire limits".into(),
            )
        })?;
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
        ABI_VERSION, ActorId, CallExpirationEnvelopeV2, CallTimeoutV2, ConsistencyBaseV2,
        DeploymentId, EXECUTION_SEMANTICS_ID, Hash, InvocationId, ProgramId, PublicationAckV2,
        RootServiceId, ServiceIdentityV2, SpaceId, WorkInputIdV2,
    };
    use vos_raft::{Meta, Storage, WriteBatch};

    fn request(byte: u8) -> AccumulateRequestV2 {
        AccumulateRequestV2::AcknowledgePublication(PublicationAckV2 {
            service: ServiceIdentityV2 {
                space: SpaceId([2; 32]),
                root_service: RootServiceId([byte; 32]),
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

    fn expiration_request() -> AccumulateRequestV2 {
        let service = request(1).service().clone();
        let caller_invocation = InvocationId([9; 32]);
        let await_ordinal = 2;
        AccumulateRequestV2::ExpireCall(CallExpirationEnvelopeV2 {
            service,
            timeout: CallTimeoutV2 {
                call_id: caller_invocation.call_id(await_ordinal),
                caller_invocation,
                caller_actor: ActorId([10; 32]),
                checkpoint_step: 1,
                await_ordinal,
                deadline_timeslot: 50,
                expired_at: 50,
            },
            base: ConsistencyBaseV2::Linear {
                revision: 3,
                state_root: Hash([11; 32]),
            },
            base_causal_height: None,
            crdt_change: None,
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

    fn proof_artifact(byte: u8) -> ImportedBlobV2 {
        let bytes = vec![byte; 32];
        ImportedBlobV2 {
            reference: crate::v2::BlobRefV2::of_bytes(&bytes),
            bytes,
        }
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
        log.mark_applied(1, &service_image, &[]).unwrap();
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
    fn replicated_timeout_payload_pins_the_ambient_jam_slot() {
        let bytes = expiration_request().encode();
        assert!(RaftAccumulatePayloadV2::from_request(&bytes, None).is_err());
        assert!(RaftAccumulatePayloadV2::from_request(&request(1).encode(), Some(50)).is_err());

        let (path, directory) = temp_path();
        let mut log = RaftAccumulateLogV2::open(&path, RaftConfig::default()).unwrap();
        let committed = log.propose_at(&bytes, Some(50)).unwrap();
        assert_eq!(committed.request, bytes);
        assert_eq!(committed.logical_timeslot, Some(50));
        drop(log);

        let mut restarted = RaftAccumulateLogV2::open(&path, RaftConfig::default()).unwrap();
        assert_eq!(
            restarted.committed_after(0).unwrap().entries,
            vec![committed]
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn compaction_freezes_the_exact_applied_service_image() {
        let (path, directory) = temp_path();
        let db = Arc::new(Database::create(&path).unwrap());
        let mut log = RaftAccumulateLogV2::from_db_arc(db.clone(), RaftConfig::default()).unwrap();
        let first = log.propose(&request(1).encode()).unwrap();
        let first_image = service_image(1);
        log.mark_applied(first.index, &first_image, &[]).unwrap();
        let second = log.propose(&request(2).encode()).unwrap();
        let second_image = service_image(2);
        let second_proof = proof_artifact(9);
        log.mark_applied(
            second.index,
            &second_image,
            core::slice::from_ref(&second_proof),
        )
        .unwrap();
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
        assert!(frozen.proof_artifacts.is_empty());

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
        assert_eq!(frozen.proof_artifacts, vec![second_proof]);
        drop(storage);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn v2_compaction_fails_closed_when_the_exact_image_is_missing() {
        let (path, directory) = temp_path();
        let db = Arc::new(Database::create(&path).unwrap());
        let mut log = RaftAccumulateLogV2::from_db_arc(db.clone(), RaftConfig::default()).unwrap();
        let entry = log.propose(&request(1).encode()).unwrap();
        log.mark_applied(entry.index, &service_image(1), &[])
            .unwrap();
        drop(log);

        let transaction = db.begin_write().unwrap();
        {
            let mut table = transaction
                .open_table(super::super::redb_storage::RAFT_APPLIED_STATE_V2)
                .unwrap();
            table.remove(entry.index).unwrap();
        }
        transaction.commit().unwrap();

        let mut storage = RedbStorage::open(db.clone()).unwrap();
        assert!(
            futures_executor::block_on(storage.commit_batch(WriteBatch {
                compact_to: Some((entry.index, 0)),
                ..Default::default()
            }))
            .is_err(),
            "a v2 log prefix cannot be discarded without its exact service image"
        );
        assert_eq!(RaftMeta::load(&db).unwrap().snap_last_index, 0);
        assert_eq!(
            RaftLog::open(db).unwrap().term_at(entry.index).unwrap(),
            Some(0)
        );
        drop(storage);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn applied_service_image_history_is_bounded_without_worker_compaction() {
        use redb::ReadableTable;

        let (path, directory) = temp_path();
        let db = Arc::new(Database::create(&path).unwrap());
        let mut log = RaftAccumulateLogV2::from_db_arc(db.clone(), RaftConfig::default()).unwrap();
        let total = super::super::redb_storage::RAFT_APPLIED_STATE_V2_RETENTION + 4;
        for index in 1..=total {
            let entry = log.propose(&request(index as u8).encode()).unwrap();
            assert_eq!(entry.index, index);
            log.mark_applied(entry.index, &service_image(index as u8), &[])
                .unwrap();
        }
        drop(log);

        let transaction = db.begin_read().unwrap();
        let table = transaction
            .open_table(super::super::redb_storage::RAFT_APPLIED_STATE_V2)
            .unwrap();
        let keys = table
            .iter()
            .unwrap()
            .map(|row| row.unwrap().0.value())
            .collect::<Vec<_>>();
        assert_eq!(
            keys.len() as u64,
            super::super::redb_storage::RAFT_APPLIED_STATE_V2_RETENTION + 1,
            "the marker plus only the recent exact-image window are retained"
        );
        assert_eq!(keys[0], 0);
        assert_eq!(
            keys[1],
            total - super::super::redb_storage::RAFT_APPLIED_STATE_V2_RETENTION + 1
        );
        drop(table);
        drop(transaction);
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
            proof_artifacts: vec![],
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
        log.mark_applied(4, &service_image, &[]).unwrap();
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
        log.mark_applied(2, &service_image, &[]).unwrap();
        assert_eq!(log.applied_index().unwrap(), 2);

        drop(log);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
