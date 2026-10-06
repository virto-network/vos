//! Live clean-network attachment for journal-backed Shared Agents.
//!
//! This module owns the only bridge from `/vos/agent/3.0.0` to a
//! `SharedAgentHost`. Every inbound frame has already crossed Noise PeerId
//! authentication and exact route membership in `agent_network`; this layer
//! then dispatches typed Raft, invocation, and Merge work to the durable
//! generation backend. Observers remain authenticated route/Merge members but
//! deliberately never own a `vos_raft` worker.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    Arc, Condvar, Mutex, RwLock,
    atomic::{AtomicBool, Ordering},
    mpsc as std_mpsc,
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use libp2p::PeerId;
use redb::Database;
use vos_agent_sdk::{
    Hash, InvocationAuthorization, InvocationScope, InvocationWork, MethodMode, NodeId,
    RuntimeExecutionContext, RuntimeOutcome,
};
use vos_raft::{ActiveConfigRecord, EntryKind, LogEntry, Meta, Storage, WriteBatch};

use crate::agent::genesis::AgentReplicaCommittee;
use crate::agent::host::LocalMergeAuthenticator;
use crate::agent::journal::{
    CanonicalJournalRecord, MAX_IMPORT_BYTES, MAX_IMPORT_EVENTS, MAX_JOURNAL_RECORD_BYTES,
    MAX_MERGE_FRONTIER_ENTRIES, MAX_REPLAY_SUFFIX_BYTES, MAX_REPLAY_SUFFIX_ENTRIES, MergeEvent,
    MergeEventId, ReplayInputId,
};
use crate::agent::shared_commit::{
    SharedAgentCommonSnapshotCertificate, SharedAgentSnapshotCertificate,
};
use crate::agent::shared_host::{
    SharedAgentApplyOutcome, SharedAgentHost, SharedAgentHostError, SharedAgentRuntimeProjection,
    SharedAgentStatus, SharedAgentTransportState,
};
use crate::agent::shared_journal_driver::SharedMergeObject;
use crate::agent::shared_raft::{
    ACTIVE_CONFIG_MAGIC, META_AGENT_ACTIVE_CONFIG, META_AGENT_VOTED_FOR, META_LEGACY_ACTIVE_CONFIG,
};
use crate::agent::shared_recovery::SharedRecoveryManifest;
use crate::agent::shared_recovery::management::{
    MAX_SHARED_MANAGEMENT_RECOVERY_MEMBERS, SharedManagementRecoveryMember,
    SharedManagementRecoveryRegistration, SharedManagementRecoveryRegistrationRequest,
    SharedManagementRecoveryRelease, SharedManagementRecoveryReleaseRequest,
};
use crate::agent::{ReplicaRole, shared_raft};
use crate::commit::CommitError;
use crate::raft::{RAFT_META, RaftLog, RaftMeta};
use crate::service::wire::ServiceWire;

use super::Network;
use super::agent_network::{AGENT_REQUEST_TIMEOUT, AgentHandlerError, AgentRouteHandler};
use super::agent_protocol::{
    AgentGenerationRoute, AgentMessage, AppliedAvailabilityRequest, AuthenticatedAgentFrame,
    AuthorityReadBarrier, AuthorityReadBarrierRequest, InvocationRedirect, InvocationReply,
    ManagementRecoveryOperation, ManagementRecoveryOperationRequest, MergeMessage,
    RaftLogEntryKind, RaftMessage, RaftRole, RaftStatus, RaftVotePhase,
    invocation_request_correlation,
};
use super::agent_raft_transport::AgentRaftTransport;

const MAX_AGENT_VOTERS: usize = crate::agent::MAX_AGENT_REPLICAS;
const MAX_PENDING_ORDERED_REPLIES: usize = 1_024;
const MAX_MERGE_SYNC_SCAN_EVENTS: usize = MAX_REPLAY_SUFFIX_ENTRIES + MAX_MERGE_FRONTIER_ENTRIES;
const MAX_MERGE_SYNC_EVENTS: usize = MAX_IMPORT_EVENTS;
const MAX_MERGE_SYNC_BYTES: usize = MAX_IMPORT_BYTES;
const ORDERED_REPLY_WAIT: Duration = Duration::from_millis(1_800);

mod authority_observation;
#[cfg(target_os = "linux")]
mod forwarded_management;
mod management_recovery;

fn system_promotion_barrier(
    role: impl Fn() -> vos_raft::Role,
    snapshot: impl FnOnce() -> Option<(vos_raft::Role, u64, u64)>,
    hint_wait: Duration,
) -> Result<u64, SharedAgentHostError> {
    let deadline = Instant::now() + hint_wait;
    while role() != vos_raft::Role::Leader {
        if Instant::now() >= deadline {
            // The atomic role is only a hint: promotion may still be inside
            // a durable worker event. Consult serialized state once before
            // refusing attachment, queued behind that event. This is not a
            // hard timeout for the blocking snapshot query.
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let (role, committed, last) = snapshot().ok_or(SharedAgentHostError::Unavailable)?;
    if role != vos_raft::Role::Leader || committed != last {
        return Err(SharedAgentHostError::Unavailable);
    }
    Ok(committed)
}
const MERGE_SYNC_BUDGET: Duration = Duration::from_millis(1_500);
const MERGE_PUMP_REPLY_WAIT: Duration = Duration::from_millis(350);
const MERGE_PUMP_INTERVAL: Duration = Duration::from_millis(250);
// Reserve fixed Agent-frame/route fields plus conservative per-entry Raft
// metadata. The worker applies this count before materializing the storage
// suffix, so a batch of maximum-size legal commands remains frame-bounded.
const AGENT_RAFT_APPEND_FRAME_ENVELOPE_BYTES: usize = 1_024;
const AGENT_RAFT_APPEND_ENTRY_ENVELOPE_BYTES: usize = 64;
const MAX_SHARED_RAFT_APPEND_ENTRIES: usize = (super::agent_protocol::MAX_FRAME_BYTES
    - AGENT_RAFT_APPEND_FRAME_ENVELOPE_BYTES)
    / (shared_raft::MAX_AGENT_RAFT_COMMAND_BYTES + AGENT_RAFT_APPEND_ENTRY_ENVELOPE_BYTES);

const _: () = assert!(super::agent_protocol::MAX_MERGE_HEADS == MAX_MERGE_FRONTIER_ENTRIES);
const _: () = assert!(super::agent_protocol::MAX_RAFT_MEMBERS == MAX_AGENT_VOTERS);
const _: () =
    assert!(super::agent_protocol::MAX_FRAME_BYTES > AGENT_RAFT_APPEND_FRAME_ENVELOPE_BYTES);
const _: () = assert!(MAX_SHARED_RAFT_APPEND_ENTRIES > 0);
const _: () = assert!(MAX_SHARED_RAFT_APPEND_ENTRIES <= super::agent_protocol::MAX_RAFT_ENTRIES);
const _: () = assert!(
    MAX_SHARED_RAFT_APPEND_ENTRIES
        * (shared_raft::MAX_AGENT_RAFT_COMMAND_BYTES + AGENT_RAFT_APPEND_ENTRY_ENVELOPE_BYTES)
        + AGENT_RAFT_APPEND_FRAME_ENVELOPE_BYTES
        <= super::agent_protocol::MAX_FRAME_BYTES
);
const _: () = assert!(MAX_JOURNAL_RECORD_BYTES < shared_raft::MAX_AGENT_RAFT_COMMAND_BYTES);
const _: () = assert!(
    shared_raft::MAX_AGENT_RAFT_COMMAND_BYTES <= super::agent_protocol::MAX_RAFT_COMMAND_BYTES
);
const _: () = assert!(MAX_JOURNAL_RECORD_BYTES <= super::agent_protocol::MAX_MERGE_NODE_BYTES);

fn storage_error(message: impl Into<String>) -> CommitError {
    CommitError::Config(message.into())
}

fn valid_nodes(nodes: &[NodeId]) -> bool {
    !nodes.is_empty()
        && nodes.len() <= MAX_AGENT_VOTERS
        && nodes.iter().all(|node| *node != NodeId::ZERO)
        && nodes.windows(2).all(|pair| pair[0] < pair[1])
}

fn encode_nodes(output: &mut Vec<u8>, nodes: &[NodeId]) -> Result<(), CommitError> {
    if !valid_nodes(nodes) {
        return Err(storage_error("invalid full-NodeId Raft configuration"));
    }
    let count = u16::try_from(nodes.len())
        .map_err(|_| storage_error("full-NodeId Raft configuration exceeds bound"))?;
    output.extend_from_slice(&count.to_le_bytes());
    for node in nodes {
        output.extend_from_slice(node.as_bytes());
    }
    Ok(())
}

fn decode_nodes(bytes: &[u8], position: &mut usize) -> Result<Vec<NodeId>, CommitError> {
    let count_bytes = bytes
        .get(*position..position.saturating_add(2))
        .ok_or_else(|| storage_error("truncated full-NodeId Raft configuration"))?;
    *position += 2;
    let count = u16::from_le_bytes([count_bytes[0], count_bytes[1]]) as usize;
    if count == 0 || count > MAX_AGENT_VOTERS {
        return Err(storage_error(
            "invalid full-NodeId Raft configuration count",
        ));
    }
    let mut nodes = Vec::with_capacity(count);
    for _ in 0..count {
        let end = position
            .checked_add(32)
            .ok_or_else(|| storage_error("full-NodeId configuration overflow"))?;
        let raw: [u8; 32] = bytes
            .get(*position..end)
            .ok_or_else(|| storage_error("truncated full-NodeId Raft member"))?
            .try_into()
            .map_err(|_| storage_error("invalid full-NodeId Raft member width"))?;
        *position = end;
        nodes.push(NodeId(raw));
    }
    if !valid_nodes(&nodes) {
        return Err(storage_error(
            "non-canonical full-NodeId Raft configuration",
        ));
    }
    Ok(nodes)
}

fn encode_active_config(record: &ActiveConfigRecord<NodeId>) -> Result<Vec<u8>, CommitError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(ACTIVE_CONFIG_MAGIC);
    match record.log_index {
        Some(index) => {
            bytes.push(1);
            bytes.extend_from_slice(&index.to_le_bytes());
        }
        None => bytes.push(0),
    }
    match &record.joint_old {
        Some(nodes) => {
            bytes.push(1);
            encode_nodes(&mut bytes, nodes)?;
        }
        None => bytes.push(0),
    }
    encode_nodes(&mut bytes, &record.current)?;
    Ok(bytes)
}

fn decode_active_config(bytes: &[u8]) -> Result<ActiveConfigRecord<NodeId>, CommitError> {
    if !bytes.starts_with(ACTIVE_CONFIG_MAGIC) {
        return Err(storage_error(
            "invalid full-NodeId Raft configuration magic",
        ));
    }
    let mut position = ACTIVE_CONFIG_MAGIC.len();
    let log_index = match bytes.get(position).copied() {
        Some(0) => {
            position += 1;
            None
        }
        Some(1) => {
            position += 1;
            let end = position
                .checked_add(8)
                .ok_or_else(|| storage_error("full-NodeId config index overflow"))?;
            let raw: [u8; 8] = bytes
                .get(position..end)
                .ok_or_else(|| storage_error("truncated full-NodeId config index"))?
                .try_into()
                .map_err(|_| storage_error("invalid full-NodeId config index"))?;
            position = end;
            Some(u64::from_le_bytes(raw))
        }
        _ => return Err(storage_error("invalid full-NodeId config index tag")),
    };
    let joint_old = match bytes.get(position).copied() {
        Some(0) => {
            position += 1;
            None
        }
        Some(1) => {
            position += 1;
            Some(decode_nodes(bytes, &mut position)?)
        }
        _ => return Err(storage_error("invalid full-NodeId joint config tag")),
    };
    let current = decode_nodes(bytes, &mut position)?;
    if position != bytes.len() {
        return Err(storage_error(
            "trailing full-NodeId Raft configuration bytes",
        ));
    }
    Ok(ActiveConfigRecord {
        log_index,
        current,
        joint_old,
    })
}

/// Redb storage for the clean full-NodeId worker. It deliberately refuses
/// generic Raft snapshots: Shared-Agent snapshots require the separately
/// authenticated journal certificate/install path.
struct AgentNodeStorage {
    database: Arc<Database>,
    log: RaftLog,
    authenticated_snapshot: (u64, u64),
    #[cfg(test)]
    timing_node: NodeId,
}

impl AgentNodeStorage {
    fn open(
        database: Arc<Database>,
        authenticated_snapshot: (u64, u64),
    ) -> Result<Self, CommitError> {
        let log = RaftLog::open(Arc::clone(&database))?;
        let meta = RaftMeta::load(&database)?;
        if meta.voted_for.is_some()
            || (meta.snap_last_index, meta.snap_last_term) != authenticated_snapshot
            || (log.snap_last_index(), log.snap_last_term()) != authenticated_snapshot
            || (authenticated_snapshot.0 == 0) != (authenticated_snapshot.1 == 0)
        {
            return Err(storage_error(
                "legacy vote or mismatched authenticated snapshot in clean Agent Raft database",
            ));
        }
        let transaction = database.begin_read()?;
        if let Ok(table) = transaction.open_table(RAFT_META)
            && table.get(META_LEGACY_ACTIVE_CONFIG)?.is_some()
        {
            return Err(storage_error(
                "legacy compact Raft configuration in clean Agent database",
            ));
        }
        let storage = Self {
            database,
            log,
            authenticated_snapshot,
            #[cfg(test)]
            timing_node: NodeId::ZERO,
        };
        let _ = storage.load_exact_vote()?;
        let _ = storage.load_active_config_sync()?;
        Ok(storage)
    }

    fn load_exact_vote(&self) -> Result<Option<NodeId>, CommitError> {
        let transaction = self.database.begin_read()?;
        let table = transaction.open_table(RAFT_META)?;
        let value = table
            .get(META_AGENT_VOTED_FOR)?
            .map(|value| value.value().to_vec());
        match value {
            None => Ok(None),
            Some(bytes) => {
                let raw: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| storage_error("invalid clean Agent voted_for width"))?;
                let node = NodeId(raw);
                if node == NodeId::ZERO {
                    return Err(storage_error("zero clean Agent voted_for"));
                }
                Ok(Some(node))
            }
        }
    }

    fn load_active_config_sync(&self) -> Result<Option<ActiveConfigRecord<NodeId>>, CommitError> {
        let transaction = self.database.begin_read()?;
        let table = transaction.open_table(RAFT_META)?;
        let value = table
            .get(META_AGENT_ACTIVE_CONFIG)?
            .map(|value| value.value().to_vec());
        value.map(|bytes| decode_active_config(&bytes)).transpose()
    }
}

impl Storage<NodeId> for AgentNodeStorage {
    type Error = CommitError;

    fn last_index(&self) -> u64 {
        self.log.last_index()
    }

    fn last_term(&self) -> u64 {
        self.log.last_term()
    }

    fn snap_last_index(&self) -> u64 {
        self.log.snap_last_index()
    }

    fn snap_last_term(&self) -> u64 {
        self.log.snap_last_term()
    }

    async fn term_at(&self, index: u64) -> Result<Option<u64>, Self::Error> {
        self.log.term_at(index)
    }

    async fn entries(&self, start: u64, end: u64) -> Result<Vec<LogEntry<NodeId>>, Self::Error> {
        self.log
            .entries(start, end)?
            .into_iter()
            .map(|entry| {
                let kind = shared_raft::decode_agent_raft_entry_kind(&entry.payload)
                    .map_err(|error| storage_error(format!("invalid clean Raft slot: {error}")))?;
                Ok(LogEntry {
                    index: entry.index,
                    term: entry.term,
                    kind,
                })
            })
            .collect()
    }

    async fn read_state(&self) -> Result<Vec<u8>, Self::Error> {
        Ok(Vec::new())
    }

    async fn applied_index(&self) -> Result<Option<u64>, Self::Error> {
        Ok(Some(RaftMeta::load(&self.database)?.last_applied))
    }

    async fn load_meta(&self) -> Result<Meta<NodeId>, Self::Error> {
        let durable = RaftMeta::load(&self.database)?;
        if durable.voted_for.is_some()
            || (durable.snap_last_index, durable.snap_last_term) != self.authenticated_snapshot
        {
            return Err(storage_error("non-clean Agent Raft metadata"));
        }
        Ok(Meta {
            current_term: durable.current_term,
            voted_for: self.load_exact_vote()?,
            commit_index: durable.commit_index,
            snap_last_index: self.authenticated_snapshot.0,
            snap_last_term: self.authenticated_snapshot.1,
        })
    }

    async fn active_config(&self) -> Result<Option<ActiveConfigRecord<NodeId>>, Self::Error> {
        self.load_active_config_sync()
    }

    async fn commit_batch(&mut self, batch: WriteBatch<NodeId>) -> Result<(), Self::Error> {
        if batch.state.is_some() || batch.compact_to.is_some() {
            return Err(storage_error(
                "generic snapshot rejected for authenticated Shared-Agent journal",
            ));
        }
        let touches = batch.truncate_after.is_some()
            || !batch.appends.is_empty()
            || batch.meta.is_some()
            || batch.active_config.is_some();
        if !touches {
            return Ok(());
        }
        let cache = self.log.cache_snapshot();
        let new_meta = batch.meta.clone();
        let new_config = batch.active_config.clone();
        #[cfg(test)]
        let mut recovery_timing =
            std::env::var_os("VOS_SHARED_RECOVERY_TIMING").map(|_| (Instant::now(), None, None));
        let result = (|| -> Result<(), CommitError> {
            let transaction = self.database.begin_write()?;
            #[cfg(test)]
            if let Some((_, acquired, _)) = &mut recovery_timing {
                *acquired = Some(Instant::now());
            }
            if let Some(after) = batch.truncate_after {
                self.log.truncate_after_in_txn(&transaction, after)?;
            }
            for entry in &batch.appends {
                let encoded = shared_raft::encode_agent_raft_entry_kind(&entry.kind)
                    .map_err(|error| storage_error(format!("invalid clean Raft slot: {error}")))?;
                let assigned = self.log.append_in_txn(&transaction, entry.term, &encoded)?;
                if assigned != entry.index {
                    return Err(storage_error("non-contiguous clean Agent Raft append"));
                }
            }
            if let Some(meta) = &new_meta {
                if (meta.snap_last_index, meta.snap_last_term) != self.authenticated_snapshot
                    || meta.commit_index > self.log.last_index()
                    || meta.commit_index < self.authenticated_snapshot.0
                {
                    return Err(storage_error("invalid clean Agent Raft metadata advance"));
                }
                // `last_applied` belongs to the Shared journal application
                // transaction, which uses the same database but an
                // independent storage object. Reload it inside this write
                // transaction so a Raft metadata update can never regress a
                // concurrently completed application after restart.
                let current = RaftMeta::load_from_write_transaction(&transaction)?;
                if current.last_applied > meta.commit_index {
                    return Err(storage_error("clean Agent apply cursor exceeds commit"));
                }
                let durable = RaftMeta {
                    current_term: meta.current_term,
                    voted_for: None,
                    commit_index: meta.commit_index,
                    last_applied: current.last_applied,
                    snap_last_index: self.authenticated_snapshot.0,
                    snap_last_term: self.authenticated_snapshot.1,
                };
                durable.write_worker_fields_in_txn(&transaction)?;
                let mut table = transaction.open_table(RAFT_META)?;
                match meta.voted_for {
                    Some(node) if node != NodeId::ZERO => {
                        table.insert(META_AGENT_VOTED_FOR, node.as_bytes().as_slice())?;
                    }
                    Some(_) => return Err(storage_error("zero clean Agent voted_for")),
                    None => {
                        table.remove(META_AGENT_VOTED_FOR)?;
                    }
                }
            }
            if let Some(config) = &new_config {
                let encoded = encode_active_config(config)?;
                let mut table = transaction.open_table(RAFT_META)?;
                table.insert(META_AGENT_ACTIVE_CONFIG, encoded.as_slice())?;
            }
            #[cfg(test)]
            if let Some((_, _, prepared)) = &mut recovery_timing {
                *prepared = Some(Instant::now());
            }
            transaction.commit()?;
            Ok(())
        })();
        #[cfg(test)]
        if let Some((started, acquired, prepared)) = recovery_timing {
            let finished = Instant::now();
            eprintln!(
                "raft_write node={:?} term={:?} commit={:?} appends={} first={:?} last={:?} truncate={:?} wait_us={:?} prepare_us={:?} commit_us={:?} total_us={} success={}",
                self.timing_node,
                new_meta.as_ref().map(|meta| meta.current_term),
                new_meta.as_ref().map(|meta| meta.commit_index),
                batch.appends.len(),
                batch.appends.first().map(|entry| entry.index),
                batch.appends.last().map(|entry| entry.index),
                batch.truncate_after,
                acquired.map(|time| time.duration_since(started).as_micros()),
                acquired
                    .zip(prepared)
                    .map(|(start, end)| end.duration_since(start).as_micros()),
                prepared.map(|time| finished.duration_since(time).as_micros()),
                finished.duration_since(started).as_micros(),
                result.is_ok(),
            );
        }
        if let Err(error) = result {
            self.log.cache_restore(cache);
            return Err(error);
        }
        Ok(())
    }
}

fn protocol_route_from(
    generation: crate::agent::shared_raft::AgentGenerationRouteKey,
    replication_id: [u8; 32],
) -> AgentGenerationRoute {
    AgentGenerationRoute {
        space: vos_agent_sdk::SpaceId(generation.space().0),
        agent: vos_agent_sdk::AgentId(generation.agent().0),
        generation: Hash(replication_id),
    }
}

fn route_members_from(
    replicas: &[crate::agent::shared_host::SharedReplicaRoute],
    transition: Option<&crate::agent::shared_host::SharedCommitteeTransitionRoute>,
) -> Result<Vec<(NodeId, PeerId)>, SharedAgentHostError> {
    let mut by_node = BTreeMap::new();
    let replicas = replicas.iter().chain(
        transition
            .iter()
            .flat_map(|transition| transition.next_replicas.iter()),
    );
    for replica in replicas {
        let peer = PeerId::from_bytes(&replica.peer_id)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let peer_bytes = peer.to_bytes();
        let node = NodeId(replica.node.0);
        if peer_bytes != replica.peer_id || node != NodeId::of_authenticated_peer(&peer_bytes) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if let Some(existing) = by_node.insert(node, peer)
            && existing != peer
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
    }
    Ok(by_node.into_iter().collect())
}

fn voter_nodes(replicas: &[crate::agent::shared_host::SharedReplicaRoute]) -> Vec<NodeId> {
    let mut voters = replicas
        .iter()
        .filter(|replica| replica.role == ReplicaRole::Voter)
        .map(|replica| NodeId(replica.node.0))
        .collect::<Vec<_>>();
    voters.sort_unstable();
    voters
}

fn raft_configuration_from(
    replicas: &[crate::agent::shared_host::SharedReplicaRoute],
    transition: Option<&crate::agent::shared_host::SharedCommitteeTransitionRoute>,
) -> (Vec<NodeId>, Option<Vec<NodeId>>) {
    let active = voter_nodes(replicas);
    match transition {
        Some(transition) if transition.joint => {
            (voter_nodes(&transition.next_replicas), Some(active))
        }
        _ => (active, None),
    }
}

fn reply_for_outcome(request: Hash, outcome: RuntimeOutcome) -> AgentMessage {
    AgentMessage::InvokeReply(InvocationReply { request, outcome })
}

fn has_applied_availability_quorum(voters: &[NodeId], available: &BTreeSet<NodeId>) -> bool {
    matches!(voters.len(), 1 | 3)
        && valid_nodes(voters)
        && voters
            .iter()
            .filter(|voter| available.contains(voter))
            .count()
            > voters.len() / 2
}

enum OrderedReplyState {
    Waiting,
    Ready(RuntimeOutcome),
    Failed,
}

#[derive(Default)]
struct OrderedReplyWaiters {
    replies: Mutex<BTreeMap<ReplayInputId, OrderedReplyState>>,
    changed: Condvar,
}

impl OrderedReplyWaiters {
    fn register(&self, input: ReplayInputId) -> Result<(), AgentHandlerError> {
        let mut replies = self.replies.lock().map_err(|_| AgentHandlerError)?;
        if replies.len() == MAX_PENDING_ORDERED_REPLIES || replies.contains_key(&input) {
            return Err(AgentHandlerError);
        }
        replies.insert(input, OrderedReplyState::Waiting);
        Ok(())
    }

    fn cancel(&self, input: ReplayInputId) {
        if let Ok(mut replies) = self.replies.lock() {
            replies.remove(&input);
            self.changed.notify_all();
        }
    }

    fn collect_from(
        &self,
        host: &mut SharedAgentHost,
        agent: crate::service::AgentId,
    ) -> Result<(), SharedAgentHostError> {
        let inputs = self
            .replies
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .iter()
            .filter_map(|(input, state)| {
                matches!(state, OrderedReplyState::Waiting).then_some(*input)
            })
            .collect::<Vec<_>>();
        if inputs.is_empty() {
            return Ok(());
        }
        let mut completed = Vec::new();
        for input in inputs {
            if let Some(outcome) = host.try_take_clean_ordered_result(agent, input)? {
                completed.push((input, outcome));
            }
        }
        if completed.is_empty() {
            return Ok(());
        }
        let mut replies = self
            .replies
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        for (input, outcome) in completed {
            if matches!(replies.get(&input), Some(OrderedReplyState::Waiting)) {
                replies.insert(input, OrderedReplyState::Ready(outcome));
            }
        }
        self.changed.notify_all();
        Ok(())
    }

    fn fail_all(&self) {
        if let Ok(mut replies) = self.replies.lock() {
            for state in replies.values_mut() {
                if matches!(state, OrderedReplyState::Waiting) {
                    *state = OrderedReplyState::Failed;
                }
            }
            self.changed.notify_all();
        }
    }

    fn wait(&self, input: ReplayInputId) -> Result<RuntimeOutcome, AgentHandlerError> {
        let deadline = Instant::now() + ORDERED_REPLY_WAIT;
        let diagnostic_started = std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS")
            .is_some()
            .then(Instant::now);
        let trace_failure = |reason: &'static str| {
            if let Some(started) = diagnostic_started {
                tracing::debug!(
                    ?input,
                    reason,
                    elapsed_us = started.elapsed().as_micros(),
                    "Ordered reply waiter failed"
                );
            }
        };
        let mut replies = self.replies.lock().map_err(|_| {
            trace_failure("reply_lock_poisoned");
            AgentHandlerError
        })?;
        loop {
            match replies.get(&input) {
                Some(OrderedReplyState::Ready(_)) => {
                    let Some(OrderedReplyState::Ready(outcome)) = replies.remove(&input) else {
                        unreachable!("reply state was checked while holding the same lock")
                    };
                    return Ok(outcome);
                }
                Some(OrderedReplyState::Failed) => {
                    trace_failure("failed");
                    replies.remove(&input);
                    return Err(AgentHandlerError);
                }
                None => {
                    trace_failure("missing");
                    replies.remove(&input);
                    return Err(AgentHandlerError);
                }
                Some(OrderedReplyState::Waiting) => {}
            }
            let now = Instant::now();
            if now >= deadline {
                trace_failure("waiting_timeout");
                replies.remove(&input);
                return Err(AgentHandlerError);
            }
            let (next, timeout) = self
                .changed
                .wait_timeout(replies, deadline.saturating_duration_since(now))
                .map_err(|_| {
                    trace_failure("reply_wait_poisoned");
                    AgentHandlerError
                })?;
            replies = next;
            if timeout.timed_out()
                && matches!(replies.get(&input), Some(OrderedReplyState::Waiting))
            {
                trace_failure("waiting_timeout");
                replies.remove(&input);
                return Err(AgentHandlerError);
            }
        }
    }
}

fn drain_committed(
    host: &mut SharedAgentHost,
    agent: crate::service::AgentId,
    waiters: &OrderedReplyWaiters,
) -> Result<(), SharedAgentHostError> {
    loop {
        match host.apply_next(agent)? {
            SharedAgentApplyOutcome::Applied { .. } | SharedAgentApplyOutcome::Duplicate { .. } => {
            }
            SharedAgentApplyOutcome::Idle => break,
        }
    }
    waiters.collect_from(host, agent)
}

fn merge_object_needs_staging(object: &SharedMergeObject) -> bool {
    matches!(object, SharedMergeObject::Missing)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AttachmentFingerprint {
    protocol_route: AgentGenerationRoute,
    durable_route: crate::agent::shared_raft::AgentRouteKey,
    members: Vec<(NodeId, PeerId)>,
    next_committee: Option<crate::agent::genesis::AgentReplicaCommitteeId>,
    next_voters: Option<Vec<NodeId>>,
    voters: Vec<NodeId>,
    joint_old: Option<Vec<NodeId>>,
    local_role: ReplicaRole,
}

impl AttachmentFingerprint {
    fn from_attachment_status(
        status: &crate::agent::shared_host::SharedAgentAttachmentStatus,
    ) -> Result<Self, SharedAgentHostError> {
        let members = route_members_from(&status.replicas, status.committee_transition.as_ref())?;
        let (voters, joint_old) =
            raft_configuration_from(&status.replicas, status.committee_transition.as_ref());
        let next_voters = status
            .committee_transition
            .as_ref()
            .map(|transition| voter_nodes(&transition.next_replicas));
        if !valid_nodes(&voters)
            || joint_old.as_ref().is_some_and(|nodes| !valid_nodes(nodes))
            || next_voters
                .as_ref()
                .is_some_and(|nodes| !valid_nodes(nodes))
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        Ok(Self {
            protocol_route: protocol_route_from(status.generation, status.replication_id),
            durable_route: status.route,
            members,
            next_committee: status
                .committee_transition
                .as_ref()
                .map(|transition| transition.next_committee),
            next_voters,
            voters,
            joint_old,
            local_role: status
                .local_role
                .ok_or(SharedAgentHostError::ScopeMismatch)?,
        })
    }

    fn validates_local(&self, local: NodeId) -> bool {
        if self.next_committee.is_some() != self.next_voters.is_some() {
            return false;
        }
        let member = self
            .members
            .binary_search_by_key(&local, |(node, _)| *node)
            .is_ok();
        let voter = self.voters.binary_search(&local).is_ok();
        let joint_voter = self
            .joint_old
            .as_ref()
            .is_some_and(|nodes| nodes.binary_search(&local).is_ok());
        let next_voter = self
            .next_voters
            .as_ref()
            .is_some_and(|nodes| nodes.binary_search(&local).is_ok());
        member
            && match self.local_role {
                ReplicaRole::Voter => voter || joint_voter,
                // An authenticated observer stays a non-worker unless an
                // already-authorized next committee promotes it. Such a node
                // must start as a follower before the joint entry can reach
                // and activate it.
                ReplicaRole::Observer => !joint_voter && (!voter || next_voter),
            }
    }

    fn requires_promotion_barrier(
        &self,
        explicit: bool,
        implicit_system: bool,
        pending_management: bool,
        management_retirement: bool,
    ) -> bool {
        let fixed_three = self.members.len() == 3
            && self.voters.len() == 3
            && self
                .members
                .iter()
                .map(|(node, _)| *node)
                .eq(self.voters.iter().copied())
            && self.local_role == ReplicaRole::Voter
            && self.next_committee.is_none()
            && self.next_voters.is_none()
            && self.joint_old.is_none();
        explicit || pending_management || management_retirement || (implicit_system && !fixed_three)
    }

    fn owns_raft_worker(&self, local: NodeId) -> bool {
        self.voters.binary_search(&local).is_ok()
            || self
                .joint_old
                .as_ref()
                .is_some_and(|nodes| nodes.binary_search(&local).is_ok())
            || self
                .next_voters
                .as_ref()
                .is_some_and(|nodes| nodes.binary_search(&local).is_ok())
    }
}

struct SharedRouteHandler {
    host: Arc<Mutex<SharedAgentHost>>,
    network: Arc<Network>,
    route: AgentGenerationRoute,
    agent: crate::service::AgentId,
    route_nodes: Vec<NodeId>,
    management_retention: bool,
    worker: Option<vos_raft::WorkerHandle<NodeId>>,
    proposal: Mutex<ProposalAdmission>,
    ordered_replies: Arc<OrderedReplyWaiters>,
    lifecycle: Arc<RwLock<bool>>,
    #[cfg(test)]
    raft_isolated: Arc<AtomicBool>,
    #[cfg(test)]
    management_custody_budget_checks: std::sync::atomic::AtomicUsize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ManagementInvocationKey {
    invocation: crate::agent_sdk::InvocationId,
    work: Hash,
    authorization: Hash,
}

impl ManagementInvocationKey {
    fn new(work: &InvocationWork, authorization: &InvocationAuthorization) -> Self {
        Self {
            invocation: work.invocation,
            work: work.commitment(),
            authorization: authorization.commitment(),
        }
    }
}

fn management_retirement_keys(
    agent: crate::service::AgentId,
    envelopes: [&crate::agent_sdk::RuntimeWork; 2],
) -> Result<[ManagementInvocationKey; 2], SharedAgentHostError> {
    let keys = [
        management_envelope_key(agent, envelopes[0])?,
        management_envelope_key(agent, envelopes[1])?,
    ];
    if keys[0].invocation == keys[1].invocation {
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    Ok(keys)
}

fn management_envelope_key(
    agent: crate::service::AgentId,
    envelope: &crate::agent_sdk::RuntimeWork,
) -> Result<ManagementInvocationKey, SharedAgentHostError> {
    let crate::agent_sdk::RuntimeWork::Invoke {
        context,
        state,
        invocation,
        authorization,
        observed_slot,
    } = envelope
    else {
        return Err(SharedAgentHostError::ScopeMismatch);
    };
    if crate::service::AgentId(invocation.agent.0) != agent
        || *context != RuntimeExecutionContext::Direct
        || *state != crate::agent_sdk::RuntimeState::default()
        || !invocation.validate()
        || invocation.mode != crate::agent_sdk::MethodMode::Linear
        || **authorization
            != InvocationAuthorization::PublicPreflight(
                crate::agent_sdk::PublicPreflight::for_work(invocation, *observed_slot),
            )
    {
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    Ok(ManagementInvocationKey::new(invocation, authorization))
}

type PendingManagement = (
    crate::agent::clean_management_intent::ManagementJournalAnchor,
    crate::agent_sdk::RuntimeWork,
);
type ManagementPublicationGuard<'a> = dyn FnMut(
    &PendingManagement,
    Option<&crate::agent::shared_recovery::management::SharedManagementRecoverySlot>,
    &[PendingManagement],
    &[[crate::agent_sdk::RuntimeWork; 2]],
    bool,
) -> Result<(), SharedAgentHostError> + 'a;
type PendingManagementKey = (
    ManagementInvocationKey,
    crate::agent::clean_management_intent::ManagementJournalAnchor,
);

fn pending_management_keys(
    agent: crate::service::AgentId,
    pending: &[PendingManagement],
) -> Result<Vec<PendingManagementKey>, SharedAgentHostError> {
    if pending.is_empty() || pending.len() > MAX_REPLAY_SUFFIX_ENTRIES {
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    let mut seen = BTreeSet::new();
    pending
        .iter()
        .map(|(anchor, work)| {
            let key = management_envelope_key(agent, work)?;
            if !seen.insert(key.invocation) {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            Ok((key, anchor.clone()))
        })
        .collect()
}

fn pending_management_refs(
    pending: &[PendingManagement],
) -> Vec<(
    &crate::agent::clean_management_intent::ManagementJournalAnchor,
    &crate::agent_sdk::RuntimeWork,
)> {
    pending
        .iter()
        .map(|(anchor, work)| (anchor, work))
        .collect()
}

#[derive(Default)]
struct ProposalAdmission {
    checkpoint_gate: Option<ManagementInvocationKey>,
    management_retirement: Option<Vec<[ManagementInvocationKey; 2]>>,
    management_pending: Option<Vec<PendingManagementKey>>,
}

fn management_retirement_set_keys(
    agent: crate::service::AgentId,
    pairs: &[[&crate::agent_sdk::RuntimeWork; 2]],
) -> Result<Vec<[ManagementInvocationKey; 2]>, SharedAgentHostError> {
    if pairs.is_empty() || pairs.len() > MAX_REPLAY_SUFFIX_ENTRIES / 2 {
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    let mut seen = BTreeSet::new();
    pairs
        .iter()
        .map(|pair| {
            let keys = management_retirement_keys(agent, *pair)?;
            if keys.iter().any(|key| !seen.insert(key.invocation)) {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            Ok(keys)
        })
        .collect()
}

fn retirement_pair_refs(
    pairs: &[[crate::agent_sdk::RuntimeWork; 2]],
) -> Vec<[&crate::agent_sdk::RuntimeWork; 2]> {
    pairs.iter().map(|pair| [&pair[0], &pair[1]]).collect()
}

impl ProposalAdmission {
    fn is_reserved(&self) -> bool {
        self.checkpoint_gate.is_some()
            || self.management_retirement.is_some()
            || self.management_pending.is_some()
    }
}

#[derive(Clone, Copy)]
enum ReservedSubmission {
    ManagementRetirement(ManagementInvocationKey),
    ManagementResult(ManagementInvocationKey),
    ManagementCustody {
        owner: NodeId,
        registration: Hash,
        member: Hash,
    },
}

#[derive(Clone, Copy)]
enum InvocationClock<'a> {
    Current,
    Bootstrap,
    PersistedManagement(&'a crate::agent::clean_management_intent::ManagementJournalAnchor),
}

#[derive(Clone, Copy)]
enum SupervisorAdmission<'a> {
    Ordinary,
    ReservedManagementRetirement,
    ReservedManagementResult,
    PersistedManagement(&'a crate::agent::clean_management_intent::ManagementJournalAnchor),
}

#[cfg(test)]
pub(crate) fn trace_common_checkpoint_material_for_test(
    label: &str,
    node: crate::service::NodeId,
    claim: &crate::agent::shared_commit::SharedAgentCommonSnapshotClaim,
    manifest: &SharedRecoveryManifest,
) {
    eprintln!(
        "common_material label={label} node={node:?} claim={:?} ordered={:?} raft={}/{} ancestry={:?} claim_recovery={:?} manifest={:?}",
        claim.commitment().0,
        claim.ordered().commitment().0,
        claim.ordered().raft_index(),
        claim.ordered().raft_term(),
        claim.ancestry(),
        claim.recovery_manifest().map(|root| root.0),
        manifest.commitment().0
    );
}

/// Result of one authenticated clean Ordered submission through the live
/// Raft worker. A retained external response is proved against the current
/// authenticated root, not assigned a fabricated historical input identity.
pub(crate) struct CleanOrderedSubmission {
    pub(crate) input: Option<ReplayInputId>,
    pub(crate) outcome: RuntimeOutcome,
    pub(crate) new_slot: bool,
}

/// Result of clean management admission through the live Raft worker.
/// Guest denial is explicitly nondurable; every successful unseen request is
/// applied from a real committed Ordered slot.
pub(crate) enum CleanManagementSubmission {
    Denied {
        outcome: RuntimeOutcome,
        observed_slot: u64,
    },
    Applied {
        outcome: RuntimeOutcome,
        observed_slot: u64,
        new_slot: bool,
    },
}

fn quiescent_proposal_commit(
    role: vos_raft::Role,
    committed: u64,
    last: u64,
    allow_follower_retention: bool,
) -> Result<u64, SharedAgentHostError> {
    if committed != last
        || !(role == vos_raft::Role::Leader
            || (allow_follower_retention && role == vos_raft::Role::Follower))
    {
        return Err(SharedAgentHostError::Unavailable);
    }
    Ok(committed)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CommittedProposalBarrier {
    role: vos_raft::Role,
    term: u64,
    committed: u64,
    last: u64,
}

impl From<&vos_raft::WorkerSnapshot<NodeId>> for CommittedProposalBarrier {
    fn from(snapshot: &vos_raft::WorkerSnapshot<NodeId>) -> Self {
        Self {
            role: snapshot.role,
            term: snapshot.current_term,
            committed: snapshot.commit_index,
            last: snapshot.last_log_index,
        }
    }
}

impl CommittedProposalBarrier {
    fn validate_applied(self, current: Self, applied: u64) -> Result<(), SharedAgentHostError> {
        // Raft can advance while the caller waits for the host or drains its
        // committed rows. Such progress invalidates the sample, not the store.
        if self != current {
            return Err(SharedAgentHostError::Unavailable);
        }
        if applied != self.committed {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        Ok(())
    }
}

/// Transport setup is not permission to propose or sign. Before the route is
/// installed this worker cannot receive heartbeats, so an election can change
/// its role/term during the host audit without changing any ordered data.
/// Retained management attachment requires the complete stable authenticated
/// prefix instead; operation admission continues to use CommittedProposalBarrier.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RetainedAttachmentBarrier {
    committed: u64,
    last: u64,
    snapshot: u64,
    members: Vec<NodeId>,
    joint_old: Option<Vec<NodeId>>,
    configuration: Option<u64>,
    retirement: Option<u64>,
}

impl From<&vos_raft::WorkerSnapshot<NodeId>> for RetainedAttachmentBarrier {
    fn from(snapshot: &vos_raft::WorkerSnapshot<NodeId>) -> Self {
        Self {
            committed: snapshot.commit_index,
            last: snapshot.last_log_index,
            snapshot: snapshot.snap_last_index,
            members: snapshot.members.clone(),
            joint_old: snapshot.joint_old.clone(),
            configuration: snapshot.active_config_index,
            retirement: snapshot.retirement_final_index,
        }
    }
}

impl RetainedAttachmentBarrier {
    fn validate_scope(&self, voters: &[NodeId], snapshot: u64) -> Result<(), SharedAgentHostError> {
        if self.committed != self.last {
            return Err(SharedAgentHostError::Unavailable);
        }
        if self.members != voters
            || self.joint_old.is_some()
            || self.configuration.is_none()
            || self.retirement.is_some()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if self.snapshot != snapshot {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        Ok(())
    }

    fn validate_applied(&self, current: &Self, applied: u64) -> Result<(), SharedAgentHostError> {
        if self != current || current.committed != current.last {
            return Err(SharedAgentHostError::Unavailable);
        }
        if applied != self.committed {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        Ok(())
    }
}

impl SharedRouteHandler {
    /// Collect a fixed-three common checkpoint certificate. Callers retain
    /// the checkpoint admission gate, but neither host nor proposal locks may
    /// cross peer I/O. Every signature is checked over the same exact claim.
    fn collect_common_snapshot_certificate(
        &self,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
    ) -> Result<SharedAgentCommonSnapshotCertificate, SharedAgentHostError> {
        let (fingerprint, candidate, signature) = {
            let mut host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            drain_committed(&mut host, self.agent, &self.ordered_replies)?;
            let status = host
                .supervisor_attachment_status(self.agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?;
            let fingerprint = AttachmentFingerprint::from_attachment_status(&status)?;
            if status.transport != SharedAgentTransportState::Attached
                || fingerprint.protocol_route != self.route
                || fingerprint.next_committee.is_some()
                || fingerprint.joint_old.is_some()
                || fingerprint.voters.len() != 3
                || fingerprint
                    .voters
                    .binary_search(&self.network.agent_node_id())
                    .is_err()
                || signer.node().0 != self.network.agent_node_id().0
            {
                return Err(SharedAgentHostError::SnapshotCertificateInvalid);
            }
            let candidate = host.request_common_snapshot_compaction(self.agent)?;
            if candidate.claim().active_committee() != expected_committee {
                return Err(SharedAgentHostError::SnapshotCertificateInvalid);
            }
            let signature = signer
                .sign_common_snapshot_candidate(&candidate)
                .filter(|signature| signature.signer() == signer.node())
                .ok_or(SharedAgentHostError::SnapshotCertificateInvalid)?;
            #[cfg(test)]
            if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                if let Ok(manifest) = host.recovery_manifest(self.agent) {
                    trace_common_checkpoint_material_for_test(
                        "expected",
                        signer.node(),
                        candidate.claim(),
                        &manifest,
                    );
                }
            }
            (fingerprint, candidate, signature)
        };
        let local = self.network.agent_node_id();
        #[cfg(test)]
        if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
            eprintln!(
                "common_vote expected node={local:?} claim={:?} ordered={:?} raft={}/{} ancestry={:?} recovery={:?}",
                candidate.claim().commitment(),
                candidate.claim().ordered().commitment(),
                candidate.claim().ordered().raft_index(),
                candidate.claim().ordered().raft_term(),
                candidate.claim().ancestry(),
                candidate.claim().recovery_manifest()
            );
        }
        let deadline = Instant::now() + ORDERED_REPLY_WAIT;
        let mut pending = BTreeMap::new();
        for &voter in &fingerprint.voters {
            if voter != local {
                pending.insert(
                    voter,
                    self.network.send_agent_common_snapshot_vote(
                        voter,
                        self.route,
                        candidate.claim().clone(),
                    ),
                );
            }
        }
        let certificate = loop {
            let mut finished = Vec::new();
            let mut verified = None;
            for (&voter, response) in &pending {
                match response.try_recv() {
                    Ok(Ok(Some(remote))) if remote.signer().0 == voter.0 => {
                        let mut signatures = vec![signature.clone(), remote];
                        signatures.sort_unstable_by_key(|signature| signature.signer());
                        if let Ok(certificate) = SharedAgentCommonSnapshotCertificate::new(
                            candidate.claim().clone(),
                            signatures,
                        ) {
                            if certificate
                                .verify(expected_committee, candidate.claim())
                                .is_ok()
                            {
                                verified = Some(certificate);
                            }
                        }
                        finished.push(voter);
                    }
                    Ok(response) => {
                        #[cfg(test)]
                        if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                            eprintln!(
                                "common_vote refused node={local:?} voter={voter:?} response={response:?}"
                            );
                        }
                        finished.push(voter);
                    }
                    Err(std_mpsc::TryRecvError::Disconnected) => finished.push(voter),
                    Err(std_mpsc::TryRecvError::Empty) => {}
                }
            }
            if let Some(certificate) = verified {
                break certificate;
            }
            for voter in finished {
                pending.remove(&voter);
            }
            if pending.is_empty() || Instant::now() >= deadline {
                #[cfg(test)]
                if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                    eprintln!(
                        "common_vote unavailable node={local:?} pending={} expired={}",
                        pending.len(),
                        Instant::now() >= deadline
                    );
                }
                return Err(SharedAgentHostError::Unavailable);
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let status = host
            .supervisor_attachment_status(self.agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if status.transport != SharedAgentTransportState::Attached
            || AttachmentFingerprint::from_attachment_status(&status)? != fingerprint
        {
            return Err(SharedAgentHostError::SnapshotCertificateInvalid);
        }
        host.verify_common_snapshot_candidate(self.agent, candidate.claim())?;
        Ok(certificate)
    }

    /// Result delivery requires applied *state* on a majority, not merely a
    /// committed Raft command on a majority. This evidence is ephemeral and
    /// recollected after restart; it is not snapshot/compaction authority.
    fn require_ordered_availability(
        &self,
        input: ReplayInputId,
    ) -> Result<(), SharedAgentHostError> {
        let started = Instant::now();
        #[cfg(test)]
        let trace = |phase: &str| {
            if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                eprintln!(
                    "availability_phase node={:?} input={input:?} phase={phase} elapsed_us={}",
                    self.network.agent_node_id(),
                    started.elapsed().as_micros()
                );
            }
        };
        let (fingerprint, local, request) = {
            let mut host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let status = host
                .supervisor_attachment_status(self.agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?;
            let fingerprint = AttachmentFingerprint::from_attachment_status(&status)?;
            if fingerprint.protocol_route != self.route
                || fingerprint.next_committee.is_some()
                || fingerprint.joint_old.is_some()
                || !matches!(fingerprint.voters.len(), 1 | 3)
            {
                return Err(SharedAgentHostError::Unavailable);
            }
            let local = NodeId(host.scope().node.0);
            if fingerprint.voters.binary_search(&local).is_err() {
                return Err(SharedAgentHostError::Unavailable);
            }
            // Callers already obtained this exact result from a durable
            // application or verified retained-result path. For an image
            // singleton that is its entire quorum, including results now
            // retained in an authenticated snapshot whose old anchor was
            // compacted. Preserve that existing path; external generations
            // still require exact block-availability evidence below.
            if fingerprint.voters.len() == 1 && !host.uses_external_state(self.agent)? {
                return Ok(());
            }
            let claim = host
                .available_ordered_claim(self.agent, input)
                .map_err(|error| {
                    #[cfg(test)]
                    trace(&format!("local_claim_error={error:?}"));
                    error
                })?;
            if claim.committee() != fingerprint.durable_route.committee() {
                return Err(SharedAgentHostError::Unavailable);
            }
            let request = AppliedAvailabilityRequest {
                raft_index: claim.raft_index(),
                raft_term: claim.raft_term(),
                claim: Hash(claim.commitment().0),
            };
            (fingerprint, local, request)
        };
        #[cfg(test)]
        trace("local_material");
        self.collect_applied_availability(fingerprint, local, request, false, started)
    }

    /// The current-root mode is additive: historical replies still attest
    /// their original publications, while retained inspection needs this exact
    /// current state available on a voter majority.
    fn collect_applied_availability(
        &self,
        fingerprint: AttachmentFingerprint,
        local: NodeId,
        request: AppliedAvailabilityRequest,
        current_root: bool,
        started: Instant,
    ) -> Result<(), SharedAgentHostError> {
        // No host/proposal mutex may cross peer I/O: each voter needs its
        // independent apply handler to reach and attest this exact state.
        let mut available = BTreeSet::from([local]);
        let deadline = started + ORDERED_REPLY_WAIT;
        let mut pending = BTreeMap::new();
        while !has_applied_availability_quorum(&fingerprint.voters, &available) {
            if Instant::now() >= deadline {
                return Err(SharedAgentHostError::Unavailable);
            }
            for &voter in &fingerprint.voters {
                if !available.contains(&voter) && !pending.contains_key(&voter) {
                    let reply = if current_root {
                        self.network
                            .send_agent_current_applied_availability(voter, self.route, request)
                    } else {
                        self.network
                            .send_agent_applied_availability(voter, self.route, request)
                    };
                    pending.insert(voter, reply);
                }
            }
            let mut finished = Vec::new();
            for (&voter, response) in &pending {
                match response.try_recv() {
                    Ok(Ok(true)) => {
                        available.insert(voter);
                        finished.push(voter);
                    }
                    Ok(_) => finished.push(voter),
                    Err(std_mpsc::TryRecvError::Disconnected) => finished.push(voter),
                    Err(std_mpsc::TryRecvError::Empty) => {}
                }
            }
            for voter in finished {
                pending.remove(&voter);
            }
            if !has_applied_availability_quorum(&fingerprint.voters, &available) {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        // A committee/attachment change during collection invalidates these
        // votes. Missing local data cannot be hidden by two remote replies.
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let status = host
            .supervisor_attachment_status(self.agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if AttachmentFingerprint::from_attachment_status(&status)? != fingerprint {
            return Err(SharedAgentHostError::Unavailable);
        }
        if current_root {
            #[cfg(feature = "experimental-state-blocks")]
            host.verify_current_ordered_availability(
                self.agent,
                request.raft_index,
                request.raft_term,
                crate::service::Hash(request.claim.0),
            )?;
            #[cfg(not(feature = "experimental-state-blocks"))]
            return Err(SharedAgentHostError::Unavailable);
        } else {
            host.verify_ordered_availability(
                self.agent,
                request.raft_index,
                request.raft_term,
                crate::service::Hash(request.claim.0),
            )?;
        }
        tracing::debug!(
            agent = ?self.agent, ?request, current_root, voters = available.len(),
            elapsed_us = started.elapsed().as_micros(),
            "Shared result applied-availability quorum"
        );
        Ok(())
    }

    #[cfg(feature = "experimental-state-blocks")]
    fn require_retained_external_availability(
        &self,
        request: &crate::agent::shared_journal_driver::CleanInvocationReplayRequest,
        proof: &crate::agent::shared_journal_driver::RetainedExternalReplyProof,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        let started = Instant::now();
        let (fingerprint, local, availability) = {
            let mut host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let status = host
                .supervisor_attachment_status(self.agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?;
            let fingerprint = AttachmentFingerprint::from_attachment_status(&status)?;
            let local = NodeId(host.scope().node.0);
            if fingerprint.protocol_route != self.route
                || fingerprint.next_committee.is_some()
                || fingerprint.joint_old.is_some()
                || fingerprint.voters.len() != 3
                || fingerprint.voters.binary_search(&local).is_err()
                || proof.claim().committee() != fingerprint.durable_route.committee()
            {
                return Err(SharedAgentHostError::Unavailable);
            }
            host.revalidate_external_retained_reply(self.agent, request, proof)?;
            let availability = AppliedAvailabilityRequest {
                raft_index: proof.claim().raft_index(),
                raft_term: proof.claim().raft_term(),
                claim: Hash(proof.claim().commitment().0),
            };
            (fingerprint, local, availability)
        };
        self.collect_applied_availability(fingerprint, local, availability, true, started)?;
        // The same guest-proved head and exact request must still be live at
        // delivery. Root advancement during peer I/O is a retry, not a new read.
        self.host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .revalidate_external_retained_reply(self.agent, request, proof)
    }

    fn has_local_proposer(&self, worker: &vos_raft::WorkerHandle<NodeId>) -> bool {
        if worker.role() == vos_raft::Role::Leader {
            return true;
        }
        // A freshly reopened one-voter generation has no remote leader to
        // redirect to. Give its real Raft worker one bounded election window
        // before reporting unavailability to the bootstrap state machine.
        if self.route_nodes.len() != 1 {
            return false;
        }
        let deadline = Instant::now() + ORDERED_REPLY_WAIT;
        while worker.role() != vos_raft::Role::Leader {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        true
    }

    /// Capture and durably record a pre-dispatch anchor while proposals and
    /// checkpoint selection are excluded. The callback may only write the
    /// independent intent store; it must not re-enter this host or coordinator.
    fn record_management_anchor<F, T>(
        &self,
        envelope: &crate::agent_sdk::RuntimeWork,
        record: F,
    ) -> Result<T, SharedAgentHostError>
    where
        F: FnOnce(
            crate::agent::clean_management_intent::ManagementJournalAnchor,
        ) -> Result<T, SharedAgentHostError>,
    {
        let proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if proposal.is_reserved() {
            return Err(SharedAgentHostError::Conflict);
        }
        let worker = self
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if !self.has_local_proposer(worker) {
            return Err(SharedAgentHostError::Unavailable);
        }
        let barrier = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        if barrier.role != vos_raft::Role::Leader || barrier.commit_index != barrier.last_log_index
        {
            return Err(SharedAgentHostError::Unavailable);
        }
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, self.agent, &self.ordered_replies)?;
        let current = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        CommittedProposalBarrier::from(&barrier).validate_applied(
            CommittedProposalBarrier::from(&current),
            host.capacity(self.agent)?.0,
        )?;
        let position = host.journal_position(self.agent)?;
        // Validate envelope scope without executing policy or the runtime.
        host.management_invocation_after(self.agent, &position, envelope)?;
        record(
            crate::agent::clean_management_intent::ManagementJournalAnchor {
                genesis: position.genesis,
                admission: position.admission,
                runtime: position.runtime.commitment(),
                ordered: crate::agent::journal::OrderedBase {
                    index: position.ordered_index,
                    head: position.ordered_head,
                },
            },
        )
    }

    /// Commit existing typed retention metadata without holding the host over
    /// worker/peer I/O. The caller retains proposal exclusion. An unavailable
    /// reply is never dispatch permission: retry must drain a fresh committed
    /// barrier and inspect the exact manifest before publishing an intent.
    fn commit_management_metadata(
        &self,
        worker: &vos_raft::WorkerHandle<NodeId>,
        barrier: &vos_raft::WorkerSnapshot<NodeId>,
        fingerprint: &AttachmentFingerprint,
        command: &shared_raft::AgentRaftCommand,
    ) -> Result<(), SharedAgentHostError> {
        command
            .validate()
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let deadline = Instant::now() + ORDERED_REPLY_WAIT;
        let started = std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS")
            .is_some()
            .then(Instant::now);
        let diagnostic = started.map(|_| match command {
            shared_raft::AgentRaftCommand::RegisterManagementRecovery { registration, .. } => (
                "register",
                Some(registration.commitment()),
                registration.request().members().last().map(|member| {
                    ManagementInvocationKey::new(member.work(), member.authorization())
                }),
            ),
            shared_raft::AgentRaftCommand::ReleaseManagementRecovery { release, .. } => {
                ("release", Some(release.commitment()), None)
            }
            _ => ("unsupported", None, None),
        });
        let trace = |phase: &str| {
            if let (Some(started), Some((kind, metadata, key))) = (started, diagnostic) {
                tracing::debug!(node = ?self.network.agent_node_id().0, agent = ?self.agent.0,
                    route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                    thread = ?std::thread::current().id(),
                    kind, metadata = ?metadata.map(|value| value.0),
                    invocation = ?key.map(|key| key.invocation.0),
                    work = ?key.map(|key| key.work.0), authorization = ?key.map(|key| key.authorization.0),
                    phase, elapsed_us = started.elapsed().as_micros(),
                    "management_metadata_commit");
            }
        };
        let trace_poll = |phase: &'static str, status: &'static str, poll: u64, phase_started: Option<Instant>| {
            if let (Some(phase_started), Some((kind, metadata, key))) = (phase_started, diagnostic) {
                tracing::debug!(node = ?self.network.agent_node_id().0, agent = ?self.agent.0,
                    route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                    thread = ?std::thread::current().id(),
                    kind, metadata = ?metadata.map(|value| value.0),
                    invocation = ?key.map(|key| key.invocation.0),
                    work = ?key.map(|key| key.work.0), authorization = ?key.map(|key| key.authorization.0),
                    phase, status, poll, elapsed_us = phase_started.elapsed().as_micros(),
                    "VOS causal management");
            }
        };
        let refused = |phase: &str, error: SharedAgentHostError| {
            trace(phase);
            if started.is_some() {
                tracing::debug!(node = ?self.network.agent_node_id().0, agent = ?self.agent.0,
                    route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                    thread = ?std::thread::current().id(),
                    metadata = ?diagnostic.and_then(|(_, metadata, _)| metadata).map(|value| value.0), phase, ?error,
                    "management_metadata_commit refusal");
            }
            error
        };
        trace("start");
        // Keep the transport receiver alive, but never make a reply a
        // prerequisite for observing our independently applied command. The
        // reply may be lost after commit, or wait behind peer validation.
        let _reply_hint;
        if barrier.role == vos_raft::Role::Follower {
            let leader = self
                .management_leader(barrier)
                .map_err(|error| refused("leader_unavailable", error))?;
            if started.is_some() {
                tracing::debug!(node = ?self.network.agent_node_id().0, agent = ?self.agent.0,
                    leader = ?leader.0, role = ?barrier.role, term = barrier.current_term,
                    committed = barrier.commit_index, last = barrier.last_log_index,
                    "management_metadata_commit forward");
            }
            _reply_hint = Some(self.network.send_agent_management_recovery_command(
                leader,
                self.route,
                command.clone(),
            ));
            trace("forward_sent");
            // A reply, including true, is only a scheduling hint. Dispatch and
            // cleanup require the origin's independently applied manifest below.
        } else if barrier.role == vos_raft::Role::Leader {
            _reply_hint = None;
            trace("propose_start");
            let index = futures_executor::block_on(worker.propose_if_prefix(
                command.encode(),
                barrier.current_term,
                barrier.last_log_index,
                barrier.commit_index,
            ))
            .map_err(|_| refused("propose_error", SharedAgentHostError::Unavailable))?;
            if barrier.last_log_index.checked_add(1) != Some(index) {
                return Err(refused(
                    "propose_prefix_mismatch",
                    SharedAgentHostError::Unavailable,
                ));
            }
            trace("propose_complete");
        } else {
            return Err(refused(
                "role_unavailable",
                SharedAgentHostError::Unavailable,
            ));
        }
        trace("local_custody_wait_start");
        let mut diagnostic_poll = 0u64;
        let mut diagnostic_frontier = None;
        loop {
            if started.is_some() {
                diagnostic_poll = diagnostic_poll.saturating_add(1);
            }
            let phase_started = started.map(|_| Instant::now());
            let host_result = self
                .host
                .lock()
                .map_err(|_| refused("wait_host_lock_error", SharedAgentHostError::Unavailable));
            trace_poll("metadata_host_wait", if host_result.is_ok() { "ok" } else { "error" }, diagnostic_poll, phase_started);
            let mut host = host_result?;
            let phase_started = started.map(|_| Instant::now());
            let drain_result = drain_committed(&mut host, self.agent, &self.ordered_replies)
                .map_err(|error| refused("wait_host_drain_error", error));
            trace_poll("metadata_drain", if drain_result.is_ok() { "ok" } else { "error" }, diagnostic_poll, phase_started);
            drain_result?;
            let status = host
                .supervisor_attachment_status(self.agent)
                .map_err(|error| refused("wait_attachment_error", error))?
                .ok_or_else(|| {
                    refused(
                        "wait_attachment_missing",
                        SharedAgentHostError::AgentNotFound,
                    )
                })?;
            if status.transport != SharedAgentTransportState::Attached
                || &AttachmentFingerprint::from_attachment_status(&status)
                    .map_err(|error| refused("wait_fingerprint_error", error))?
                    != fingerprint
            {
                return Err(refused(
                    "wait_attachment_scope_error",
                    SharedAgentHostError::ScopeMismatch,
                ));
            }
            let phase_started = started.map(|_| Instant::now());
            let manifest_result = host
                .recovery_manifest(self.agent)
                .map_err(|error| refused("wait_manifest_error", error));
            trace_poll("metadata_manifest", if manifest_result.is_ok() { "ok" } else { "error" }, diagnostic_poll, phase_started);
            let manifest = manifest_result?;
            let committed = match command {
                shared_raft::AgentRaftCommand::RegisterManagementRecovery {
                    registration, ..
                } => manifest
                    .management_slot(registration.owner())
                    .is_some_and(|slot| slot.registration() == registration),
                shared_raft::AgentRaftCommand::ReleaseManagementRecovery { release, .. } => {
                    manifest
                        .management_slot(release.request().owner())
                        .is_some_and(|slot| slot.release() == Some(release))
                }
                _ => {
                    return Err(refused(
                        "command_scope_error",
                        SharedAgentHostError::ScopeMismatch,
                    ));
                }
            };
            if let (Some(started), Some((kind, metadata, key))) = (started, diagnostic) {
                // Position comparison is diagnostic only. Equal retained
                // frontiers do not authenticate equal manifest or state bytes.
                let frontier = manifest.management_slots().iter()
                    .map(|slot| slot.last_position()).max().unwrap_or((0, 0));
                tracing::debug!(node = ?self.network.agent_node_id().0, agent = ?self.agent.0,
                    route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                    thread = ?std::thread::current().id(),
                    kind, metadata = ?metadata.map(|value| value.0),
                    invocation = ?key.map(|key| key.invocation.0),
                    work = ?key.map(|key| key.work.0), authorization = ?key.map(|key| key.authorization.0),
                    phase = "metadata_poll", status = if committed { "present" } else { "absent" },
                    poll = diagnostic_poll, elapsed_us = started.elapsed().as_micros(),
                    retained_index = frontier.0, retained_term = frontier.1,
                    prior_frontier = diagnostic_frontier.is_some(),
                    retained_frontier_equal = diagnostic_frontier == Some(frontier),
                    "VOS causal management");
                diagnostic_frontier = Some(frontier);
            }
            if committed {
                trace("local_custody_complete");
                return Ok(());
            }
            drop(host);
            if Instant::now() >= deadline {
                return Err(refused(
                    "local_custody_timeout",
                    SharedAgentHostError::Unavailable,
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Native-only pledge after the exact durable lifecycle terminal. Runtime
    /// ACKs alone never invoke this method or release the parent obligation.
    fn release_management_retention(
        &self,
        root: &crate::agent_sdk::RuntimeWork,
    ) -> Result<(), SharedAgentHostError> {
        let key = management_envelope_key(self.agent, root)?;
        let diagnostic_started = std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS")
            .is_some().then(Instant::now);
        let _proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let worker = self
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let barrier = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        quiescent_proposal_commit(
            barrier.role,
            barrier.commit_index,
            barrier.last_log_index,
            true,
        )?;
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, self.agent, &self.ordered_replies)?;
        #[cfg(test)]
        let capacity_audits_before = host.capacity_audits_for_test(self.agent)?;
        let (applied, remaining, _) = host.capacity(self.agent)?;
        let status = host
            .supervisor_attachment_status(self.agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        let fingerprint = AttachmentFingerprint::from_attachment_status(&status)?;
        if fingerprint.members.len() == 1 {
            // Historical singleton management has no replicated retention.
            return Ok(());
        }
        if status.transport != SharedAgentTransportState::Attached
            || fingerprint.protocol_route != self.route
            || fingerprint.members.len() != 3
            || fingerprint.voters.len() != 3
            || fingerprint.next_committee.is_some()
            || fingerprint.joint_old.is_some()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let manifest = host.recovery_manifest(self.agent)?;
        let Some(slot) =
            manifest.management_slot(crate::service::NodeId(self.network.agent_node_id().0))
        else {
            // A historical terminal predates scoped retention. This native
            // pledge neither fabricates custody nor releases another scope.
            return Ok(());
        };
        if slot.members().first().map(|member| member.envelope()) != Some(root) {
            if slot
                .members()
                .iter()
                .any(|member| member.work().invocation == key.invocation)
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            // Exact retry of an older durable terminal must not release or
            // interfere with the owner's later family. Replacement itself
            // requires the preceding signed release; retain the current slot.
            return Ok(());
        }
        if slot.is_released() {
            return Ok(());
        }
        if barrier.role != vos_raft::Role::Leader && barrier.role != vos_raft::Role::Follower {
            return Err(SharedAgentHostError::Unavailable);
        }
        let request = SharedManagementRecoveryReleaseRequest::for_slot(slot)
            .map_err(|_| SharedAgentHostError::Conflict)?;
        if let Some(started) = diagnostic_started {
            tracing::debug!(node = ?self.network.agent_node_id().0, agent = ?self.agent.0,
                route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                thread = ?std::thread::current().id(),
                genesis = ?request.generation().genesis().as_bytes(),
                admission = ?request.generation().admission().as_bytes(),
                committee = ?request.committee().as_bytes(), owner = ?request.owner().0,
                scope = ?request.scope().0, registration = ?slot.registration().commitment().0,
                root_member = ?slot.members().first().map(|member| member.commitment().0),
                invocation = ?key.invocation.0, work = ?key.work.0, authorization = ?key.authorization.0,
                sequence = request.sequence(), phase = "release_scope_binding", status = "verified_scope",
                poll = 0u64, elapsed_us = started.elapsed().as_micros(),
                "VOS causal management");
        }
        // The complete tuple came from the first audit after the drain.
        // Only read-only attachment and exact manifest/request checks have
        // run under these uninterrupted proposal/host guards. Consume it
        // before signing; no tuple crosses signing, storage or peer work.
        if remaining < 2 {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        #[cfg(test)]
        assert_eq!(
            host.capacity_audits_for_test(self.agent)?,
            capacity_audits_before + 1,
            "native release preparation must perform one capacity audit before signing"
        );
        let (candidate, signature) =
            host.prepare_signed_management_recovery_release(self.agent, &request)?;
        let release = SharedManagementRecoveryRelease::new(candidate.request().clone(), signature)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        if let Some(started) = diagnostic_started {
            tracing::debug!(node = ?self.network.agent_node_id().0, agent = ?self.agent.0,
                route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                thread = ?std::thread::current().id(),
                genesis = ?release.request().generation().genesis().as_bytes(),
                admission = ?release.request().generation().admission().as_bytes(),
                committee = ?release.request().committee().as_bytes(), owner = ?release.request().owner().0,
                metadata = ?release.commitment().0, scope = ?release.request().scope().0,
                registration = ?Some(slot.registration().commitment().0),
                root_member = ?slot.members().first().map(|member| member.commitment().0),
                invocation = ?Some(key.invocation.0), work = ?Some(key.work.0), authorization = ?Some(key.authorization.0),
                sequence = release.request().sequence(), phase = "release_binding", status = "signed_candidate",
                poll = 0u64, elapsed_us = started.elapsed().as_micros(), "VOS causal management");
        }
        let command = shared_raft::AgentRaftCommand::ReleaseManagementRecovery {
            route: status.route,
            release,
        };
        let current = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        CommittedProposalBarrier::from(&barrier)
            .validate_applied(CommittedProposalBarrier::from(&current), applied)?;
        drop(host);
        self.commit_management_metadata(worker, &current, &fingerprint, &command)
    }

    /// Extend an existing recovery reservation before publishing an intent
    /// image. A failed callback may have committed: retain the exact candidate
    /// in both admission and the attachment's refresh image even on failure.
    fn extend_management_pending<F, T>(
        &self,
        pending: &mut Vec<PendingManagement>,
        retiring: &[[crate::agent_sdk::RuntimeWork; 2]],
        predecessor: Option<&PendingManagement>,
        retain_management: bool,
        fresh_only: bool,
        mut before_publication: Option<&mut ManagementPublicationGuard<'_>>,
        proposed: &crate::agent_sdk::RuntimeWork,
        record: F,
    ) -> Result<T, SharedAgentHostError>
    where
        F: FnOnce(&PendingManagement) -> Result<T, SharedAgentHostError>,
    {
        let key = management_envelope_key(self.agent, proposed)?;
        let diagnostic_started = std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS")
            .is_some().then(Instant::now);
        let trace_capture = |phase: &'static str| {
            if let Some(started) = diagnostic_started {
                tracing::debug!(node = ?self.network.agent_node_id().0, agent = ?self.agent.0,
                    route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                    thread = ?std::thread::current().id(), invocation = ?key.invocation.0,
                    work = ?key.work.0, authorization = ?key.authorization.0,
                    phase, status = "candidate", poll = 0u64,
                    elapsed_us = started.elapsed().as_micros(), "VOS causal management");
            }
        };
        if fresh_only && (!retain_management || predecessor.is_some() || !pending.is_empty() || !retiring.is_empty()) {
            return Err(SharedAgentHostError::Conflict);
        }
        trace_capture("capture_proposal_start");
        let mut proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        trace_capture("capture_proposal_acquired");
        let pending_keys = if pending.is_empty() {
            None
        } else {
            Some(pending_management_keys(self.agent, pending)?)
        };
        if proposal.checkpoint_gate.is_some() || proposal.management_pending != pending_keys {
            return Err(SharedAgentHostError::Conflict);
        }
        if let Some(predecessor) = predecessor {
            if !pending.contains(predecessor)
                || management_envelope_key(self.agent, &predecessor.1)?.invocation == key.invocation
            {
                return Err(SharedAgentHostError::Conflict);
            }
        } else if !retiring.is_empty()
            || (!pending.is_empty()
                && (pending.len() != 1
                    || management_envelope_key(self.agent, &pending[0].1)?.invocation
                        != key.invocation))
        {
            // Initial capture may only retry its own single reserved member.
            // It cannot append another request or bypass a retirement gate.
            return Err(SharedAgentHostError::Conflict);
        }
        let retiring_keys = if retiring.is_empty() {
            None
        } else {
            Some(management_retirement_set_keys(
                self.agent,
                &retirement_pair_refs(retiring),
            )?)
        };
        if proposal.management_retirement != retiring_keys
            || retiring_keys.as_ref().is_some_and(|pairs| {
                pairs
                    .iter()
                    .flatten()
                    .any(|old| old.invocation == key.invocation)
            })
        {
            return Err(SharedAgentHostError::Conflict);
        }
        // After an ambiguous write, the caller may propose a later clock.
        // Reuse the reserved envelope, never replace its signed-call identity
        // or authorization clock. Canonical envelope validation is above and
        // in pending_management_keys for both candidates.
        let existing = pending.iter().find(|(_, work)| {
            management_envelope_key(self.agent, work)
                .is_ok_and(|old| old.invocation == key.invocation)
        });
        if let Some((_, saved)) = existing {
            let (
                crate::agent_sdk::RuntimeWork::Invoke {
                    invocation: saved, ..
                },
                crate::agent_sdk::RuntimeWork::Invoke {
                    invocation: proposed,
                    ..
                },
            ) = (saved, proposed)
            else {
                return Err(SharedAgentHostError::ScopeMismatch);
            };
            if saved != proposed {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
        }
        let worker = self
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if !(retain_management && self.management_retention) && !self.has_local_proposer(worker) {
            return Err(SharedAgentHostError::Unavailable);
        }
        trace_capture("capture_worker_start");
        let barrier = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        trace_capture("capture_worker_complete");
        quiescent_proposal_commit(
            barrier.role,
            barrier.commit_index,
            barrier.last_log_index,
            retain_management && self.management_retention,
        )?;
        trace_capture("capture_host_start");
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        trace_capture("capture_host_acquired");
        drain_committed(&mut host, self.agent, &self.ordered_replies)?;
        trace_capture("capture_host_drained");
        let (applied_slots, remaining_slots, _) = host.capacity(self.agent)?;
        let current = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        CommittedProposalBarrier::from(&barrier)
            .validate_applied(CommittedProposalBarrier::from(&current), applied_slots)?;
        // Singleton System keeps its historical management lane. The custody
        // manifest is a fixed-three contract, not an empty singleton fallback.
        let fixed_three_retention = if retain_management {
            let status = host
                .supervisor_attachment_status(self.agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?;
            AttachmentFingerprint::from_attachment_status(&status)?
                .members
                .len()
                == 3
        } else {
            false
        };
        if !fixed_three_retention && barrier.role != vos_raft::Role::Leader {
            return Err(SharedAgentHostError::Unavailable);
        }
        let retained_member = if fixed_three_retention {
            let manifest = host.recovery_manifest(self.agent)?;
            if fresh_only && manifest.management_slots().iter().any(|slot| {
                slot.members().iter().any(|member| member.work().invocation == key.invocation)
            }) {
                // A released or forwarded copy of this same call is still old
                // custody. Unrelated released slots remain ordinary predecessors.
                return Err(SharedAgentHostError::Conflict);
            }
            manifest
                .management_slot(crate::service::NodeId(self.network.agent_node_id().0))
                .filter(|slot| !slot.is_released())
                .and_then(|slot| {
                    slot.members()
                        .iter()
                        .find(|member| member.work().invocation == key.invocation)
                        .cloned()
                })
        } else {
            None
        };
        if fresh_only && retained_member.is_some() {
            return Err(SharedAgentHostError::Conflict);
        }
        if let Some(member) = &retained_member {
            let crate::agent_sdk::RuntimeWork::Invoke { invocation, .. } = proposed else {
                return Err(SharedAgentHostError::ScopeMismatch);
            };
            if member.work() != invocation.as_ref() {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
        }
        let candidate = if let Some(existing) = existing {
            existing.clone()
        } else if let Some(member) = retained_member {
            (member.anchor().clone(), member.envelope().clone())
        } else {
            let position = host.journal_position(self.agent)?;
            (
                crate::agent::clean_management_intent::ManagementJournalAnchor {
                    genesis: position.genesis,
                    admission: position.admission,
                    runtime: position.runtime.commitment(),
                    ordered: crate::agent::journal::OrderedBase {
                        index: position.ordered_index,
                        head: position.ordered_head,
                    },
                },
                proposed.clone(),
            )
        };
        let mut combined = pending.clone();
        if existing.is_none() {
            combined.push(candidate.clone());
        }
        let keys = pending_management_keys(self.agent, &combined)?;
        let required = if predecessor.is_none() {
            host.management_initial_admission_requirement(self.agent, &candidate.0, &candidate.1)?
        } else {
            host.management_recovery_admission_requirement(
                self.agent,
                &pending_management_refs(&combined),
                &retiring.iter().flatten().collect::<Vec<_>>(),
            )?
        };
        let Some(required) = required else {
            tracing::warn!(
                agent = ?self.agent,
                initial = predecessor.is_none(),
                retained = existing.is_some(),
                applied_slots,
                remaining_slots,
                pending_members = combined.len(),
                retiring_pairs = retiring.len(),
                limit = "replay_headroom",
                "management admission capacity exhausted"
            );
            return Err(SharedAgentHostError::CapacityExhausted);
        };
        if remaining_slots < required as u64 + 1 {
            tracing::warn!(
                agent = ?self.agent,
                initial = predecessor.is_none(),
                retained = existing.is_some(),
                applied_slots,
                remaining_slots,
                required_slots = required as u64 + 1,
                pending_members = combined.len(),
                retiring_pairs = retiring.len(),
                limit = "ordered_slots",
                "management admission capacity exhausted"
            );
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        let mut publication_checked = false;
        if retain_management {
            let status = host
                .supervisor_attachment_status(self.agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?;
            let fingerprint = AttachmentFingerprint::from_attachment_status(&status)?;
            if fingerprint.members.len() == 3 {
                if status.transport != SharedAgentTransportState::Attached
                    || fingerprint.protocol_route != self.route
                    || fingerprint.voters.len() != 3
                    || fingerprint.next_committee.is_some()
                    || fingerprint.joint_old.is_some()
                {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                let manifest = host.recovery_manifest(self.agent)?;
                let owner = crate::service::NodeId(self.network.agent_node_id().0);
                let previous = manifest.management_slot(owner);
                let retained = previous.filter(|slot| !slot.is_released());
                // Keep bounded room for every allowed dependency extension,
                // the terminal release and the current-term reopen no-op.
                // Retention cannot justify admitting a scope that has no
                // remaining physical path to its durable completion.
                let metadata_remaining = MAX_SHARED_MANAGEMENT_RECOVERY_MEMBERS
                    .saturating_sub(retained.map(|slot| slot.members().len()).unwrap_or(0))
                    + 2;
                if remaining_slots < required as u64 + metadata_remaining as u64 {
                    return Err(SharedAgentHostError::CapacityExhausted);
                }
                let exact = retained.and_then(|slot| {
                    slot.members().iter().find(|member| {
                        member.anchor() == &candidate.0 && member.envelope() == &candidate.1
                    })
                });
                if exact.is_none() {
                    let parent = match predecessor {
                        Some((anchor, envelope)) => Some(
                            retained
                                .and_then(|slot| {
                                    slot.members().iter().find(|member| {
                                        member.anchor() == anchor && member.envelope() == envelope
                                    })
                                })
                                .ok_or(SharedAgentHostError::Conflict)?
                                .commitment(),
                        ),
                        None if retained.is_some() => {
                            return Err(SharedAgentHostError::Conflict);
                        }
                        None => None,
                    };
                    let mut members = retained
                        .map(|slot| slot.members().to_vec())
                        .unwrap_or_default();
                    members.push(
                        SharedManagementRecoveryMember::new(
                            parent,
                            candidate.0.clone(),
                            candidate.1.clone(),
                        )
                        .map_err(|_| SharedAgentHostError::ScopeMismatch)?,
                    );
                    // A delivery holder cannot become a replacement origin.
                    // Resolve the exact root against authenticated retained
                    // custody while proposal exclusion and the settled host
                    // prefix still cover registration publication.
                    let root = members.first().ok_or(SharedAgentHostError::ScopeMismatch)?;
                    let origin_owner = manifest
                        .management_origin_for_root(owner, root)
                        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                    if fresh_only && origin_owner != owner {
                        return Err(SharedAgentHostError::ScopeMismatch);
                    }
                    let request = SharedManagementRecoveryRegistrationRequest::new(
                        status.route.generation(),
                        status.route.committee(),
                        owner,
                        origin_owner,
                        previous
                            .map(|slot| slot.sequence())
                            .unwrap_or(0)
                            .checked_add(1)
                            .ok_or(SharedAgentHostError::CorruptResidue)?,
                        previous.map(|slot| slot.commitment()),
                        members,
                    )
                    .map_err(|_| SharedAgentHostError::CapacityExhausted)?;
                    let joint_required = host
                        .management_retention_admission_requirement_with_manifest(
                            self.agent,
                            Some(&request),
                            &manifest,
                        )?
                        .ok_or(SharedAgentHostError::CapacityExhausted)?;
                    let old_metadata = retained
                        .map(|slot| {
                            MAX_SHARED_MANAGEMENT_RECOVERY_MEMBERS
                                .saturating_sub(slot.members().len())
                                + 2
                        })
                        .unwrap_or(0);
                    let joint_metadata = Self::management_metadata_headroom(&manifest)
                        .saturating_sub(old_metadata)
                        + MAX_SHARED_MANAGEMENT_RECOVERY_MEMBERS
                            .saturating_sub(request.members().len())
                        + 3;
                    if remaining_slots < joint_required as u64 + joint_metadata as u64 {
                        return Err(SharedAgentHostError::CapacityExhausted);
                    }
                    let (registration_candidate, signature) = host
                        .prepare_signed_management_recovery_registration_with_manifest(
                            self.agent,
                            &request,
                            &manifest,
                        )?;
                    let registration = SharedManagementRecoveryRegistration::new(
                        registration_candidate.request().clone(),
                        signature,
                    )
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                    if let Some(started) = diagnostic_started {
                        let request = registration.request();
                        let registration_id = registration.commitment().0;
                        let root_member = request.members().first().map(|member| member.commitment().0);
                        for (member_index, member) in request.members().iter().enumerate() {
                            let key = ManagementInvocationKey::new(member.work(), member.authorization());
                            tracing::debug!(node = ?self.network.agent_node_id().0, agent = ?self.agent.0,
                                route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                                thread = ?std::thread::current().id(),
                                genesis = ?request.generation().genesis().as_bytes(),
                                admission = ?request.generation().admission().as_bytes(),
                                committee = ?request.committee().as_bytes(), owner = ?request.owner().0,
                                origin = ?request.origin_owner().0, registration = ?registration_id,
                                predecessor = ?request.previous().map(|value| value.0), root_member = ?root_member,
                                member_index, member = ?member.commitment().0,
                                parent = ?member.parent().map(|value| value.0),
                                invocation = ?key.invocation.0, work = ?key.work.0, authorization = ?key.authorization.0,
                                sequence = request.sequence(), phase = "family_binding", status = "signed_candidate",
                                poll = 0u64, elapsed_us = started.elapsed().as_micros(),
                                "VOS causal management");
                        }
                    }
                    let command = shared_raft::AgentRaftCommand::RegisterManagementRecovery {
                        route: status.route,
                        registration,
                    };
                    let current = futures_executor::block_on(worker.snapshot())
                        .ok_or(SharedAgentHostError::Unavailable)?;
                    CommittedProposalBarrier::from(&barrier)
                        .validate_applied(CommittedProposalBarrier::from(&current), applied_slots)
                        .map_err(|error| {
                            if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                                tracing::debug!(
                                    node = ?self.network.agent_node_id(),
                                    agent = ?self.agent,
                                    phase = "final_capture_barrier",
                                    before_role = ?barrier.role,
                                    before_term = barrier.current_term,
                                    before_committed = barrier.commit_index,
                                    before_last = barrier.last_log_index,
                                    current_role = ?current.role,
                                    current_term = current.current_term,
                                    current_committed = current.commit_index,
                                    current_last = current.last_log_index,
                                    applied_slots,
                                    ?error,
                                    "Management capture barrier refused"
                                );
                            }
                            error
                        })?;
                    if let Some(validate) = before_publication.as_mut() {
                        // No retained family or volatile pair was adopted.
                        // Mint only this open owner's fresh publication proof
                        // under the same guards, immediately before metadata I/O.
                        validate(&candidate, retained, pending, retiring, true)?;
                        publication_checked = true;
                    }
                    drop(manifest);
                    drop(host);
                    // No intent or dispatch is published on an ambiguous
                    // append. A retry first proves the entire tail committed,
                    // then recovers the original member from the manifest.
                    self.commit_management_metadata(worker, &current, &fingerprint, &command)?;
                } else if let Some(validate) = before_publication.as_mut() {
                    // Existing exact roots still require the marked complete
                    // family and original pair before the independent WAL write.
                    validate(&candidate, retained, pending, retiring, true)?;
                    publication_checked = true;
                }
            }
        }
        if !publication_checked {
            // The historical singleton lane has no registration metadata.
            // Preserve its callback recovery without adopting an old pair.
            if let Some(validate) = before_publication {
                validate(&candidate, None, pending, retiring, false)?;
            }
        }
        proposal.management_pending = Some(keys);
        *pending = combined;
        // Like anchor publication, the callback may only write the independent
        // intent store and must not re-enter the host/coordinator.
        record(&candidate)
    }

    fn reserve_management_retirement_set(
        &self,
        pairs: &[[&crate::agent_sdk::RuntimeWork; 2]],
    ) -> Result<(), SharedAgentHostError> {
        self.transition_management_retirement_set(pairs, None)
    }

    fn transition_management_retirement_set(
        &self,
        pairs: &[[&crate::agent_sdk::RuntimeWork; 2]],
        remaining_pending: Option<&[PendingManagement]>,
    ) -> Result<(), SharedAgentHostError> {
        let keys = management_retirement_set_keys(self.agent, pairs)?;
        let remaining_keys = match remaining_pending {
            Some(pending) if !pending.is_empty() => pending_management_keys(self.agent, pending)?,
            _ => Vec::new(),
        };
        let mut proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if proposal.checkpoint_gate.is_some() {
            return Err(SharedAgentHostError::Conflict);
        }
        if remaining_pending.is_none()
            && proposal
                .management_retirement
                .as_ref()
                .is_some_and(|existing| keys.iter().all(|pair| existing.contains(pair)))
        {
            return Ok(());
        }
        // Preserve every reservation exactly once. Remaining work also keeps
        // its original anchor; already-retiring pairs cannot be regrouped.
        match (&proposal.management_pending, remaining_pending) {
            (None, None) => {}
            (Some(pending), Some(_))
                if pending.len()
                    + proposal
                        .management_retirement
                        .as_ref()
                        .map_or(0, |set| set.len() * 2)
                    == keys.len() * 2 + remaining_keys.len()
                    && proposal
                        .management_retirement
                        .as_ref()
                        .is_none_or(|set| set.iter().all(|pair| keys.contains(pair)))
                    && remaining_keys.iter().all(|entry| pending.contains(entry))
                    && remaining_keys
                        .iter()
                        .all(|(key, _)| !keys.iter().flatten().any(|expected| expected == key))
                    && pending.iter().all(|entry| {
                        remaining_keys.contains(entry)
                            || keys.iter().flatten().any(|expected| expected == &entry.0)
                    }) => {}
            _ => return Err(SharedAgentHostError::Conflict),
        }
        match &proposal.management_retirement {
            Some(existing) if keys.iter().all(|pair| existing.contains(pair)) => return Ok(()),
            Some(_) if remaining_pending.is_none() => return Err(SharedAgentHostError::Conflict),
            Some(_) => {}
            None => {}
        }
        let worker = self
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if !self.management_retention && !self.has_local_proposer(worker) {
            return Err(SharedAgentHostError::Unavailable);
        }
        let barrier = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        quiescent_proposal_commit(
            barrier.role,
            barrier.commit_index,
            barrier.last_log_index,
            self.management_retention,
        )?;
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, self.agent, &self.ordered_replies)?;
        let (applied_slots, remaining_slots, _) = host.capacity(self.agent)?;
        let current = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        CommittedProposalBarrier::from(&barrier)
            .validate_applied(CommittedProposalBarrier::from(&current), applied_slots)?;
        if barrier.role == vos_raft::Role::Follower {
            let manifest = host.recovery_manifest(self.agent)?;
            let slot = manifest
                .management_slot(crate::service::NodeId(self.network.agent_node_id().0))
                .ok_or(SharedAgentHostError::ScopeMismatch)?;
            if !pairs.iter().all(|pair| {
                slot.members()
                    .iter()
                    .any(|member| member.envelope() == pair[0])
            }) || !remaining_pending
                .unwrap_or(&[])
                .iter()
                .all(|(anchor, envelope)| {
                    slot.members()
                        .iter()
                        .any(|member| member.anchor() == anchor && member.envelope() == envelope)
                })
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
        }
        let required = host
            .management_recovery_admission_requirement(
                self.agent,
                &pending_management_refs(remaining_pending.unwrap_or(&[])),
                &pairs.iter().flatten().copied().collect::<Vec<_>>(),
            )?
            .ok_or(SharedAgentHostError::CapacityExhausted)?;
        if remaining_slots < required as u64 + u64::from(required != 0) {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        proposal.management_retirement = Some(keys);
        proposal.management_pending = (!remaining_keys.is_empty()).then_some(remaining_keys);
        Ok(())
    }

    fn complete_management_retirement<F>(
        &self,
        envelopes: [&crate::agent_sdk::RuntimeWork; 2],
        complete: F,
    ) -> Result<(), SharedAgentHostError>
    where
        F: FnOnce() -> Result<(), SharedAgentHostError>,
    {
        let keys = management_retirement_keys(self.agent, envelopes)?;
        let mut proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !proposal
            .management_retirement
            .as_ref()
            .is_some_and(|set| set.contains(&keys))
            || proposal.checkpoint_gate.is_some()
        {
            return Err(SharedAgentHostError::Conflict);
        }
        if self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .management_retirement_admission_requirement(self.agent, envelopes)?
            != Some(0)
        {
            return Err(SharedAgentHostError::Conflict);
        }
        // Durable handoff must commit while all suffix-consuming ingress is
        // still excluded. An ambiguous/failed handoff retains the reservation.
        complete()?;
        let pending = proposal.management_retirement.as_mut().unwrap();
        pending.retain(|pair| *pair != keys);
        if pending.is_empty() {
            proposal.management_retirement = None;
        }
        Ok(())
    }

    /// Caller has reopened and verified the durable host completion marker.
    /// No journal lookup is needed: its bounded suffix may already be pruned.
    fn release_completed_management_retirement(
        &self,
        envelopes: [&crate::agent_sdk::RuntimeWork; 2],
    ) -> Result<(), SharedAgentHostError> {
        let keys = management_retirement_keys(self.agent, envelopes)?;
        let mut proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        match &mut proposal.management_retirement {
            None => Ok(()),
            Some(expected) if expected.contains(&keys) => {
                expected.retain(|pair| *pair != keys);
                if expected.is_empty() {
                    proposal.management_retirement = None;
                }
                Ok(())
            }
            // The verified terminal may be retried after another family has
            // entered retirement. It owns no keys in that family.
            Some(_) => Ok(()),
        }
    }

    fn release_checkpoint_gate(
        &self,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
    ) -> Result<(), SharedAgentHostError> {
        let key = ManagementInvocationKey::new(work, authorization);
        let mut proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if proposal.checkpoint_gate != Some(key) {
            return Err(SharedAgentHostError::Conflict);
        }
        proposal.checkpoint_gate = None;
        Ok(())
    }

    fn reserve_checkpoint_gate(
        &self,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
    ) -> Result<(), SharedAgentHostError> {
        let key = ManagementInvocationKey::new(work, authorization);
        let mut proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if proposal.management_retirement.is_some() || proposal.management_pending.is_some() {
            return Err(SharedAgentHostError::Conflict);
        }
        match proposal.checkpoint_gate {
            None => proposal.checkpoint_gate = Some(key),
            Some(existing) if existing == key => {}
            Some(_) => return Err(SharedAgentHostError::Conflict),
        }
        Ok(())
    }

    fn submit_clean_ordered(
        &self,
        work: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
    ) -> Result<CleanOrderedSubmission, SharedAgentHostError> {
        self.submit_clean_ordered_operation(
            crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Invoke {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                work,
                authorization,
            },
        )
    }

    fn submit_clean_ordered_operation(
        &self,
        request: crate::agent::shared_journal_driver::CleanInvocationReplayRequest,
    ) -> Result<CleanOrderedSubmission, SharedAgentHostError> {
        self.submit_clean_ordered_operation_with_policy(request, false)
    }

    fn submit_terminal_clean_ordered_operation(
        &self,
        request: crate::agent::shared_journal_driver::CleanInvocationReplayRequest,
    ) -> Result<CleanOrderedSubmission, SharedAgentHostError> {
        self.submit_clean_ordered_operation_with_policy(request, true)
    }

    fn submit_clean_ordered_operation_with_policy(
        &self,
        request: crate::agent::shared_journal_driver::CleanInvocationReplayRequest,
        terminal_only: bool,
    ) -> Result<CleanOrderedSubmission, SharedAgentHostError> {
        self.submit_clean_ordered_operation_with_admission(
            request,
            terminal_only,
            None,
            InvocationClock::Current,
        )
    }

    fn submit_clean_ordered_operation_with_admission(
        &self,
        request: crate::agent::shared_journal_driver::CleanInvocationReplayRequest,
        terminal_only: bool,
        reservation: Option<ReservedSubmission>,
        clock: InvocationClock<'_>,
    ) -> Result<CleanOrderedSubmission, SharedAgentHostError> {
        let diagnostic_node = self.network.agent_node_id();
        let diagnostic_invocation = request.work().invocation;
        let diagnostic_reserved_kind = match reservation {
            Some(ReservedSubmission::ManagementRetirement(_)) => "management_retirement",
            Some(ReservedSubmission::ManagementResult(_)) => "management_result",
            Some(ReservedSubmission::ManagementCustody { .. }) => "management_custody",
            None => "none",
        };
        let diagnostic_operation_kind = match &request {
            crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Invoke {
                ..
            } => "invoke",
            crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Resume {
                ..
            } => "resume",
            crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Acknowledge {
                ..
            } => "acknowledge",
        };
        let trace_enabled = matches!(
            reservation,
            Some(ReservedSubmission::ManagementCustody { .. })
        );
        let started = ((trace_enabled
            || matches!(clock, InvocationClock::PersistedManagement(_))
            || matches!(
                reservation,
                Some(
                    ReservedSubmission::ManagementResult(_)
                        | ReservedSubmission::ManagementRetirement(_)
                )
            ))
            && std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some())
        .then(Instant::now);
        let management_diagnostic_key =
            started.map(|_| ManagementInvocationKey::new(request.work(), request.authorization()));
        let trace = |phase: &str| {
            if let Some(started) = started {
                tracing::debug!(node = ?diagnostic_node.0, agent = ?self.agent.0,
                    route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                    thread = ?std::thread::current().id(), invocation = ?diagnostic_invocation.0,
                    work = ?management_diagnostic_key.map(|key| key.work.0),
                    authorization = ?management_diagnostic_key.map(|key| key.authorization.0),
                    reserved_kind = diagnostic_reserved_kind, operation_kind = diagnostic_operation_kind,
                    phase, elapsed_us = started.elapsed().as_micros(),
                    "management_custody_submit");
            }
        };
        let refused = |phase: &str, error: SharedAgentHostError| {
            trace(phase);
            if started.is_some() {
                tracing::debug!(node = ?diagnostic_node.0, agent = ?self.agent.0,
                    route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                    thread = ?std::thread::current().id(), invocation = ?diagnostic_invocation.0, phase, ?error,
                    "management_custody_submit refusal");
            }
            error
        };
        trace("start");
        let mut proposal = self
            .proposal
            .lock()
            .map_err(|_| refused("proposal_lock_error", SharedAgentHostError::Unavailable))?;
        trace("proposal_acquired");
        let pending_invoke = if let (Some(pending), InvocationClock::PersistedManagement(anchor)) =
            (&proposal.management_pending, clock)
        {
            let key = ManagementInvocationKey::new(request.work(), request.authorization());
            pending
                .iter()
                .any(|(expected, saved)| *expected == key && saved == anchor)
                && matches!(
                    &request,
                    crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Invoke { .. }
                )
        } else {
            false
        };
        if proposal.checkpoint_gate.is_some() {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        match (&proposal.management_retirement, reservation) {
            (_, Some(ReservedSubmission::ManagementCustody { .. })) => {},
            (_, None) if pending_invoke => {},
            (None, None) => {},
            (Some(expected), Some(ReservedSubmission::ManagementRetirement(actual)))
                if expected.iter().any(|pair| pair.contains(&actual))
                    && matches!(&request, crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Acknowledge { .. }) => {},
            (_, Some(ReservedSubmission::ManagementResult(actual)))
                if proposal.management_pending.as_ref().is_some_and(|pending| pending.iter().any(|(key, _)| *key == actual))
                    && matches!(&request, crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Acknowledge { .. }) => {},
            _ => return Err(SharedAgentHostError::CapacityExhausted),
        }
        if proposal.management_pending.is_some()
            && !pending_invoke
            && !matches!(
                reservation,
                Some(
                    ReservedSubmission::ManagementRetirement(_)
                        | ReservedSubmission::ManagementResult(_)
                        | ReservedSubmission::ManagementCustody { .. }
                )
            )
        {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        let worker = self
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if !self.has_local_proposer(worker) {
            if matches!(clock, InvocationClock::PersistedManagement(_))
                || matches!(
                    reservation,
                    Some(
                        ReservedSubmission::ManagementResult(_)
                            | ReservedSubmission::ManagementRetirement(_)
                    )
                )
            {
                drop(proposal);
                return self.forward_management_operation(request, clock);
            }
            return Err(SharedAgentHostError::Unavailable);
        }
        let ordered_barrier = if matches!(clock, InvocationClock::PersistedManagement(_))
            || matches!(
                reservation,
                Some(ReservedSubmission::ManagementCustody { .. })
            ) {
            trace("before_snapshot_start");
            let barrier = futures_executor::block_on(worker.snapshot()).ok_or_else(|| {
                refused("before_snapshot_missing", SharedAgentHostError::Unavailable)
            })?;
            trace("before_snapshot_complete");
            if started.is_some() {
                tracing::debug!(node = ?diagnostic_node.0, agent = ?self.agent.0,
                    route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                    thread = ?std::thread::current().id(), invocation = ?diagnostic_invocation.0,
                    role = ?barrier.role,
                    term = barrier.current_term, committed = barrier.commit_index,
                    last = barrier.last_log_index, "management_custody_submit barrier");
            }
            trace("strict_barrier_start");
            quiescent_proposal_commit(
                barrier.role,
                barrier.commit_index,
                barrier.last_log_index,
                false,
            )
            .map_err(|error| refused("strict_barrier_error", error))?;
            trace("strict_barrier_complete");
            Some(CommittedProposalBarrier::from(&barrier))
        } else {
            None
        };
        let input = {
            trace("host_wait_start");
            let mut host = self
                .host
                .lock()
                .map_err(|_| refused("host_lock_error", SharedAgentHostError::Unavailable))?;
            trace("host_acquired");
            trace("host_drain_start");
            drain_committed(&mut host, self.agent, &self.ordered_replies)
                .map_err(|error| refused("host_drain_error", error))?;
            trace("host_drained");
            #[cfg(test)]
            let capacity_audits_before = if trace_enabled {
                Some(host.capacity_audits_for_test(self.agent)?)
            } else {
                None
            };
            #[cfg(test)]
            let assert_single_capacity_audit = |host: &SharedAgentHost| {
                if let Some(before) = capacity_audits_before {
                    assert_eq!(
                        host.capacity_audits_for_test(self.agent).unwrap(),
                        before + 1,
                        "custody admission must obtain exactly one actual post-drain capacity audit before preparation or guard release"
                    );
                }
            };
            // Capacity is fully audited once after draining. Applied position,
            // snapshot position and reservations cannot change while these
            // host/proposal guards remain held. Reuse only for admission below,
            // never across preparation, publication or another drain.
            let mut capacity_manifest = None;
            let audited_capacity = if let Some(barrier) = ordered_barrier {
                let capacity = if matches!(
                    reservation,
                    Some(ReservedSubmission::ManagementCustody { .. })
                ) {
                    let (capacity, manifest) = host
                        .capacity_and_recovery_manifest(self.agent)
                        .map_err(|error| refused("capacity_error", error))?;
                    capacity_manifest = Some(manifest);
                    capacity
                } else {
                    host.capacity(self.agent)
                        .map_err(|error| refused("capacity_error", error))?
                };
                trace("capacity_audited");
                let current = futures_executor::block_on(worker.snapshot()).ok_or_else(|| {
                    refused(
                        "current_snapshot_missing",
                        SharedAgentHostError::Unavailable,
                    )
                })?;
                barrier
                    .validate_applied(CommittedProposalBarrier::from(&current), capacity.0)
                    .map_err(|error| refused("post_drain_barrier_error", error))?;
                Some(capacity)
            } else {
                None
            };
            let mut custody_manifest = None;
            if let Some(ReservedSubmission::ManagementCustody {
                owner,
                registration,
                member,
            }) = reservation
            {
                let (retained, manifest) = self
                    .validate_management_custody(
                        &mut host,
                        owner,
                        registration,
                        member,
                        &request,
                        clock,
                        audited_capacity
                            .ok_or(SharedAgentHostError::CorruptResidue)?
                            .1,
                        capacity_manifest.take(),
                    )
                    .map_err(|error| refused("custody_validation_error", error))?;
                trace("custody_validated");
                if let Some(retained) = retained {
                    #[cfg(test)]
                    assert_single_capacity_audit(&host);
                    drop(manifest);
                    drop(host);
                    drop(proposal);
                    trace("fresh_custody_availability_start");
                    let input = retained.input.ok_or(SharedAgentHostError::CorruptResidue)?;
                    self.require_ordered_availability(input)
                        .map_err(|error| refused("fresh_custody_availability_error", error))?;
                    trace("fresh_custody_availability_complete");
                    return Ok(retained);
                }
                if matches!(
                    (&request, clock),
                    (crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Acknowledge { .. }, InvocationClock::Current)
                        | (crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Invoke {
                            context: RuntimeExecutionContext::Direct,
                            ..
                        }, InvocationClock::PersistedManagement(_))
                ) {
                    // Freshly authenticated after draining and the strict
                    // capacity/barrier check. Lend it only under these same
                    // uninterrupted guards; discard before publication/I/O.
                    custody_manifest = Some(manifest);
                }
            }
            if self.management_retention {
                let has_pending_management = if let Some(manifest) = custody_manifest.as_ref() {
                    host.management_custody_has_pending_with_manifest(self.agent, manifest)
                        .map_err(|error| refused("management_manifest_error", error))?
                } else {
                    host.recovery_manifest(self.agent)
                        .map_err(|error| refused("management_manifest_error", error))?
                        .has_pending_management()
                };
                if has_pending_management
                    && !matches!(clock, InvocationClock::PersistedManagement(_))
                    && !matches!(
                        reservation,
                        Some(
                            ReservedSubmission::ManagementCustody { .. }
                                | ReservedSubmission::ManagementResult(_)
                                | ReservedSubmission::ManagementRetirement(_)
                        )
                    )
                {
                    // Replicate the existing exclusion: another node must not
                    // consume the offline owner's reserved completion headroom.
                    return Err(SharedAgentHostError::CapacityExhausted);
                }
            }
            let anchored_input = if let InvocationClock::PersistedManagement(anchor) = clock {
                let (applied_slots, remaining_slots, _) =
                    audited_capacity.ok_or(SharedAgentHostError::CorruptResidue)?;
                if applied_slots != ordered_barrier.unwrap().committed {
                    return Err(SharedAgentHostError::CorruptResidue);
                }
                let crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Invoke {
                    context: RuntimeExecutionContext::Direct,
                    work,
                    authorization:
                        authorization @ InvocationAuthorization::PublicPreflight(preflight),
                } = &request
                else {
                    return Err(SharedAgentHostError::ScopeMismatch);
                };
                let envelope = crate::agent_sdk::RuntimeWork::Invoke {
                    context: RuntimeExecutionContext::Direct,
                    state: crate::agent_sdk::RuntimeState::default(),
                    invocation: Box::new(work.clone()),
                    authorization: Box::new(authorization.clone()),
                    observed_slot: preflight.observed_slot,
                };
                let (required, retained) = if let Some(manifest) = custody_manifest.as_ref() {
                    host.management_pending_admission_with_input_and_manifest(
                        self.agent,
                        anchor,
                        &envelope,
                        manifest,
                    )
                } else {
                    host.management_pending_admission_with_input(self.agent, anchor, &envelope)
                }
                    .map_err(|error| refused("pending_budget_error", error))?;
                let required = required.ok_or(SharedAgentHostError::CapacityExhausted)?;
                trace("pending_budget_complete");
                if remaining_slots < required as u64 + 1 {
                    return Err(SharedAgentHostError::CapacityExhausted);
                }
                // Both values refer to the same fully validated singleton and
                // settled prefix. No prepare/drain/I/O occurs before this use;
                // preparation below must still agree with the exact input.
                trace("anchor_lookup_complete");
                Some(retained)
            } else {
                None
            };
            #[cfg(feature = "experimental-state-blocks")]
            if matches!(clock, InvocationClock::Current)
                && reservation.is_none()
                && let Some(proof) = host.inspect_external_retained_reply(self.agent, &request)?
            {
                drop(host);
                drop(proposal);
                let outcome = self.require_retained_external_availability(&request, &proof)?;
                return Ok(CleanOrderedSubmission {
                    input: None,
                    outcome,
                    new_slot: false,
                });
            }
            #[cfg(test)]
            assert_single_capacity_audit(&host);
            trace("prepare_start");
            let prepared = if matches!(clock, InvocationClock::Bootstrap) {
                host.prepare_bootstrap_invocation(self.agent, request)
            } else if matches!(clock, InvocationClock::PersistedManagement(_)) {
                if let Some(manifest) = custody_manifest.as_ref() {
                    host.prepare_persisted_management_invocation_with_manifest(
                        self.agent,
                        request,
                        manifest,
                    )
                } else {
                    host.prepare_persisted_management_invocation(self.agent, request)
                }
            } else if terminal_only {
                host.prepare_terminal_clean_ordered_operation(self.agent, request)
            } else if let Some(manifest) = custody_manifest.as_ref() {
                host.prepare_management_ack_with_manifest(self.agent, request, manifest)
            } else {
                host.prepare_clean_ordered_operation(self.agent, request)
            }
            .map_err(|error| refused("prepare_error", error))?;
            drop(custody_manifest);
            trace("prepare_complete");
            let input = prepared.input();
            if started.is_some() {
                tracing::debug!(node = ?diagnostic_node.0, agent = ?self.agent.0,
                    route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                    thread = ?std::thread::current().id(), invocation = ?diagnostic_invocation.0,
                    input = ?input.as_bytes(),
                    work = ?management_diagnostic_key.map(|key| key.work.0),
                    authorization = ?management_diagnostic_key.map(|key| key.authorization.0),
                    "management_custody_submit prepared input");
            }
            if let Some(observed) = anchored_input {
                // Preparation must agree with the authenticated interval. A
                // result predating a substituted late anchor is not a retry
                // proved by that anchor, even if another cache can find it.
                if observed != prepared.retained().map(|_| input) {
                    return Err(SharedAgentHostError::CorruptResidue);
                }
            }
            if let Some(outcome) = prepared.retained().cloned() {
                drop(host);
                drop(proposal);
                trace("retained_availability_start");
                self.require_ordered_availability(input)
                    .map_err(|error| refused("retained_availability_error", error))?;
                trace("retained_availability_complete");
                return Ok(CleanOrderedSubmission {
                    input: Some(input),
                    outcome,
                    new_slot: false,
                });
            }
            self.ordered_replies
                .register(input)
                .map_err(|_| SharedAgentHostError::Conflict)?;
            let payload = prepared
                .into_payload()
                .ok_or(SharedAgentHostError::Conflict)?;
            trace("propose_start");
            if let Err(error) = futures_executor::block_on(worker.propose(payload)) {
                tracing::debug!(?error, "clean ordered proposal did not commit");
                self.ordered_replies.cancel(input);
                return Err(refused("propose_error", SharedAgentHostError::Unavailable));
            }
            trace("propose_complete");
            input
        };
        trace("post_propose_host_wait_start");
        let mut host = self.host.lock().map_err(|_| {
            refused(
                "post_propose_host_lock_error",
                SharedAgentHostError::Unavailable,
            )
        })?;
        trace("post_propose_host_acquired");
        trace("post_propose_drain_start");
        drain_committed(&mut host, self.agent, &self.ordered_replies)
            .map_err(|error| refused("post_propose_drain_error", error))?;
        trace("post_propose_drained");
        drop(host);
        trace("wait_start");
        let outcome = self.ordered_replies.wait(input).map_err(|_| {
            if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                tracing::debug!(
                    node = ?diagnostic_node.0,
                    agent = ?self.agent.0,
                    route_space = ?self.route.space.0, route_group = ?self.route.generation.0,
                    thread = ?std::thread::current().id(), invocation = ?diagnostic_invocation.0,
                    input = ?input.as_bytes(),
                    work = ?management_diagnostic_key.map(|key| key.work.0),
                    authorization = ?management_diagnostic_key.map(|key| key.authorization.0),
                    reserved_kind = diagnostic_reserved_kind,
                    operation_kind = diagnostic_operation_kind,
                    "Ordered submission result handoff failed"
                );
            }
            tracing::debug!("clean ordered committed-result wait failed");
            refused("wait_error", SharedAgentHostError::Unavailable)
        })?;
        trace("wait_complete");
        drop(proposal);
        trace("availability_start");
        self.require_ordered_availability(input)
            .map_err(|error| refused("availability_error", error))?;
        trace("availability_complete");
        Ok(CleanOrderedSubmission {
            input: Some(input),
            outcome,
            new_slot: true,
        })
    }

    fn submit_clean_management(
        &self,
        request: crate::agent_sdk::ManagementRequest,
        authority: crate::agent_sdk::authority::AuthorityReceipt,
        artifacts: crate::agent::driver::SdkManagementArtifacts<'_>,
    ) -> Result<CleanManagementSubmission, SharedAgentHostError> {
        self.submit_clean_management_with_owner(request, authority, artifacts, None)
    }

    fn submit_clean_management_with_owner(
        &self,
        request: crate::agent_sdk::ManagementRequest,
        authority: crate::agent_sdk::authority::AuthorityReceipt,
        artifacts: crate::agent::driver::SdkManagementArtifacts<'_>,
        origin: Option<(NodeId, super::agent_protocol::ForwardedSharedInstallOwner)>,
    ) -> Result<CleanManagementSubmission, SharedAgentHostError> {
        // Capture public commitments before preparation consumes the request.
        // Local-owner dispatch is not evidence of a forwarded application.
        let forwarding_provenance = tracing::enabled!(tracing::Level::DEBUG)
            .then(|| {
                origin
                    .filter(|(sender, _)| *sender != self.network.agent_node_id())
                    .map(|(sender, _)| (sender, request.commitment(), authority.commitment()))
            })
            .flatten();
        let proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if proposal.is_reserved() {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        let worker = self
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if !self.has_local_proposer(worker) {
            return Err(SharedAgentHostError::Unavailable);
        }
        let input = {
            let mut host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            drain_committed(&mut host, self.agent, &self.ordered_replies)?;
            if let Some((sender, owner)) = origin {
                #[cfg(target_os = "linux")]
                host.validate_forwarded_shared_install_owner(
                    owner.system,
                    sender,
                    owner.registration,
                    owner.member,
                    &request,
                    &authority,
                )?;
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (sender, owner);
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
            }
            let prepared =
                host.prepare_clean_management(self.agent, request, authority, artifacts)?;
            let observed_slot = prepared.observed_slot();
            if let Some(outcome) = prepared.denied().cloned() {
                return Ok(CleanManagementSubmission::Denied {
                    outcome,
                    observed_slot,
                });
            }
            if let Some(outcome) = prepared.retained().cloned() {
                let input = prepared.input().ok_or(SharedAgentHostError::Conflict)?;
                drop(host);
                drop(proposal);
                self.require_ordered_availability(input)?;
                return Ok(CleanManagementSubmission::Applied {
                    outcome,
                    observed_slot,
                    new_slot: false,
                });
            }
            let input = prepared.input().ok_or(SharedAgentHostError::Conflict)?;
            let commands = prepared.into_commands();
            if commands.is_empty() {
                return Err(SharedAgentHostError::Conflict);
            }
            self.ordered_replies
                .register(input)
                .map_err(|_| SharedAgentHostError::Conflict)?;
            if let Some((sender, request, authority)) = forwarding_provenance {
                // This is a fresh, validated application, not upload progress
                // or a retained result. Successful local replay/availability
                // at the original owner remains required before delivery.
                tracing::debug!(
                    phase = "peer_validated_new_row",
                    node = ?self.network.agent_node_id(),
                    ?sender,
                    agent = ?self.agent,
                    route = ?self.route,
                    ?request,
                    ?authority,
                    ?input,
                    "Shared Install forwarding provenance"
                );
            }
            for payload in commands {
                if futures_executor::block_on(worker.propose(payload)).is_err() {
                    self.ordered_replies.cancel(input);
                    return Err(SharedAgentHostError::Unavailable);
                }
            }
            (input, observed_slot)
        };
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, self.agent, &self.ordered_replies)?;
        drop(host);
        let outcome = self
            .ordered_replies
            .wait(input.0)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drop(proposal);
        self.require_ordered_availability(input.0)?;
        Ok(CleanManagementSubmission::Applied {
            outcome,
            observed_slot: input.1,
            new_slot: true,
        })
    }

    fn pump_merge_once(&self, local: NodeId, stop: &AtomicBool, cursor: &mut usize) {
        let Ok(live) = self.lifecycle.read() else {
            return;
        };
        if !*live {
            return;
        }
        // One remote member per tick keeps the total work of a pump pass
        // bounded independently of committee size. The cursor gives every
        // authenticated member a fair pull opportunity across ticks.
        for _ in 0..self.route_nodes.len() {
            let peer = self.route_nodes[*cursor % self.route_nodes.len()];
            *cursor = cursor.wrapping_add(1);
            if peer == local {
                continue;
            }
            if stop.load(Ordering::Acquire) {
                return;
            }
            let Ok(Ok(heads)) = self
                .network
                .send_agent_merge_fetch_heads(peer, self.route)
                .recv_timeout(MERGE_PUMP_REPLY_WAIT)
            else {
                continue;
            };
            // A disconnected or partially-synchronized peer is ordinary.
            // `sync_merge_heads` still fails closed for malformed, unbounded,
            // or unverifiable DAG data and the next bounded pump retries from
            // the durable local frontier.
            let _ = self.sync_merge_heads(peer, heads);
            return;
        }
    }

    fn handle_invocation(
        &self,
        sender: NodeId,
        request: super::agent_protocol::InvocationRequest,
    ) -> Result<AgentMessage, AgentHandlerError> {
        if request
            .work
            .origin
            .transport_node
            .is_some_and(|node| node != sender)
        {
            return Err(AgentHandlerError);
        }
        let correlation = invocation_request_correlation(&request);
        let work = request.work;
        let authorization = request.authorization;
        match work.mode {
            MethodMode::Query | MethodMode::LinearizableQuery | MethodMode::Linear => {
                // One leader handler admits at most one uncommitted Ordered
                // invocation. This keeps the journal parent constructed below
                // exact while the independent apply thread is free to commit
                // and deliver its keyed result.
                let proposal = self.proposal.lock().map_err(|_| AgentHandlerError)?;
                if proposal.is_reserved() {
                    return Err(AgentHandlerError);
                }
                let worker = self.worker.as_ref().ok_or(AgentHandlerError)?;
                if worker.role() != vos_raft::Role::Leader {
                    let leader = worker
                        .cached_snapshot()
                        .and_then(|snapshot| snapshot.leader_hint)
                        .filter(|leader| self.route_nodes.binary_search(leader).is_ok())
                        .ok_or(AgentHandlerError)?;
                    return Ok(AgentMessage::InvokeRedirect(InvocationRedirect {
                        request: correlation,
                        leader,
                    }));
                }
                let input = {
                    // Holding the host across preparation and local Raft
                    // append prevents an apply notification from changing the
                    // journal parent between those two boundaries.
                    let mut host = self.host.lock().map_err(|_| AgentHandlerError)?;
                    drain_committed(&mut host, self.agent, &self.ordered_replies)
                        .map_err(|_| AgentHandlerError)?;
                    #[cfg(feature = "experimental-state-blocks")]
                    {
                        let exact = crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Invoke {
                            context: RuntimeExecutionContext::Direct,
                            work: work.clone(),
                            authorization: authorization.clone(),
                        };
                        if let Some(proof) = host
                            .inspect_external_retained_reply(self.agent, &exact)
                            .map_err(|_| AgentHandlerError)?
                        {
                            drop(host);
                            drop(proposal);
                            let outcome = self
                                .require_retained_external_availability(&exact, &proof)
                                .map_err(|_| AgentHandlerError)?;
                            return Ok(reply_for_outcome(correlation, outcome));
                        }
                    }
                    let prepared = host
                        .prepare_clean_ordered(self.agent, work.clone(), authorization)
                        .map_err(|_| AgentHandlerError)?;
                    if let Some(outcome) = prepared.retained().cloned() {
                        let input = prepared.input();
                        drop(host);
                        drop(proposal);
                        self.require_ordered_availability(input)
                            .map_err(|_| AgentHandlerError)?;
                        return Ok(reply_for_outcome(correlation, outcome));
                    }
                    if self.management_retention
                        && host
                            .recovery_manifest(self.agent)
                            .map_err(|_| AgentHandlerError)?
                            .has_pending_management()
                    {
                        return Err(AgentHandlerError);
                    }
                    let input = prepared.input();
                    self.ordered_replies.register(input)?;
                    let payload = prepared.into_payload().ok_or(AgentHandlerError)?;
                    if futures_executor::block_on(worker.propose(payload)).is_err() {
                        self.ordered_replies.cancel(input);
                        return Err(AgentHandlerError);
                    }
                    input
                };
                // Catch a single-node commit whose notification raced the
                // waiter after the host lock was released.
                let mut host = self.host.lock().map_err(|_| AgentHandlerError)?;
                drain_committed(&mut host, self.agent, &self.ordered_replies)
                    .map_err(|_| AgentHandlerError)?;
                drop(host);
                let outcome = self.ordered_replies.wait(input)?;
                drop(proposal);
                self.require_ordered_availability(input)
                    .map_err(|_| AgentHandlerError)?;
                Ok(reply_for_outcome(correlation, outcome))
            }
            MethodMode::Merge => {
                let proposal = self.proposal.lock().map_err(|_| AgentHandlerError)?;
                if proposal.is_reserved() {
                    return Err(AgentHandlerError);
                }
                let outcome = self
                    .host
                    .lock()
                    .map_err(|_| AgentHandlerError)?
                    .apply_clean_merge(self.agent, work, authorization)
                    .map_err(|_| AgentHandlerError)?;
                Ok(reply_for_outcome(correlation, outcome))
            }
            MethodMode::LocalQuery | MethodMode::Local => {
                let proposal = self.proposal.lock().map_err(|_| AgentHandlerError)?;
                if proposal.is_reserved() {
                    return Err(AgentHandlerError);
                }
                let outcome = self
                    .host
                    .lock()
                    .map_err(|_| AgentHandlerError)?
                    .apply_clean_local(self.agent, work, authorization)
                    .map_err(|_| AgentHandlerError)?;
                Ok(reply_for_outcome(correlation, outcome))
            }
        }
    }

    fn handle_raft(
        &self,
        sender: NodeId,
        message: RaftMessage,
    ) -> Result<AgentMessage, AgentHandlerError> {
        let worker = self.worker.as_ref().ok_or(AgentHandlerError)?;
        let response = match message {
            RaftMessage::AppendRequest {
                term,
                leader,
                prev_log_index,
                prev_log_term,
                entries,
                leader_commit,
            } => {
                let entries = entries
                    .into_iter()
                    .map(|entry| LogEntry {
                        term: entry.term,
                        index: entry.index,
                        kind: match entry.kind {
                            RaftLogEntryKind::Command(payload) => EntryKind::Data { payload },
                            RaftLogEntryKind::Configuration { members, joint_old } => {
                                EntryKind::ConfigChange { members, joint_old }
                            }
                        },
                    })
                    .collect();
                let reply = futures_executor::block_on(worker.handle_authenticated_inbound_append(
                    sender,
                    vos_raft::AppendEntriesReq {
                        term,
                        leader,
                        prev_log_index,
                        prev_log_term,
                        entries,
                        leader_commit,
                    },
                ));
                RaftMessage::AppendReply {
                    term: reply.term,
                    success: reply.success,
                    match_index: reply.match_index,
                }
            }
            RaftMessage::VoteRequest {
                phase,
                term,
                candidate,
                last_log_index,
                last_log_term,
            } => match phase {
                RaftVotePhase::Vote => {
                    let reply =
                        futures_executor::block_on(worker.handle_authenticated_inbound_vote(
                            sender,
                            vos_raft::RequestVoteReq {
                                term,
                                candidate,
                                last_log_index,
                                last_log_term,
                            },
                        ));
                    RaftMessage::VoteReply {
                        phase,
                        term: reply.term,
                        granted: reply.vote_granted,
                    }
                }
                RaftVotePhase::PreVote => {
                    let reply =
                        futures_executor::block_on(worker.handle_authenticated_inbound_prevote(
                            sender,
                            vos_raft::PreVoteReq {
                                next_term: term,
                                candidate,
                                last_log_index,
                                last_log_term,
                            },
                        ));
                    RaftMessage::VoteReply {
                        phase,
                        term: reply.term,
                        granted: reply.vote_granted,
                    }
                }
            },
            // Generic snapshot bytes are never an authenticated Shared-Agent
            // journal certificate. Refuse before the worker/storage mutates.
            RaftMessage::InstallSnapshotRequest { .. } => {
                return Err(AgentHandlerError);
            }
            RaftMessage::StatusRequest => {
                let snapshot = futures_executor::block_on(worker.snapshot());
                let last_applied = self
                    .host
                    .lock()
                    .ok()
                    .and_then(|host| host.show(self.agent).ok().flatten())
                    .map(|status| status.applied_slots)
                    .unwrap_or(0);
                return Ok(AgentMessage::Raft(RaftMessage::StatusReply(snapshot.map(
                    |snapshot| RaftStatus {
                        role: match snapshot.role {
                            vos_raft::Role::Follower => RaftRole::Follower,
                            vos_raft::Role::PreCandidate => RaftRole::PreCandidate,
                            vos_raft::Role::Candidate => RaftRole::Candidate,
                            vos_raft::Role::Leader => RaftRole::Leader,
                        },
                        current_term: snapshot.current_term,
                        commit_index: snapshot.commit_index,
                        last_applied,
                        last_log_index: snapshot.last_log_index,
                        members: snapshot.members,
                        joint_old: snapshot.joint_old,
                        active_config_index: snapshot.active_config_index,
                        leader: if snapshot.role == vos_raft::Role::Leader {
                            Some(self.network.agent_node_id())
                        } else {
                            snapshot.leader_hint
                        },
                    },
                ))));
            }
            _ => return Err(AgentHandlerError),
        };
        Ok(AgentMessage::Raft(response))
    }

    fn local_merge_heads(&self) -> Result<AgentMessage, AgentHandlerError> {
        let mut heads = self
            .host
            .lock()
            .map_err(|_| AgentHandlerError)?
            .merge_roots(self.agent)
            .map_err(|_| AgentHandlerError)?
            .into_iter()
            .map(Hash)
            .collect::<Vec<_>>();
        heads.sort_unstable();
        Ok(AgentMessage::Merge(MergeMessage::Heads(heads)))
    }

    fn sync_merge_heads(&self, sender: NodeId, heads: Vec<Hash>) -> Result<(), AgentHandlerError> {
        // An empty frontier cannot import anything. The independent apply
        // thread owns committed-log draining; this no-op must not compete
        // with management or checkpoint admission for either mutex.
        if heads.is_empty() {
            return Ok(());
        }
        // Imported Merge events consume the same authenticated composite
        // suffix budget as retained management. Hold admission for
        // the complete sync/import pass so neither ingress nor the background
        // pump can race the exact headroom check.
        let proposal = self.proposal.lock().map_err(|_| AgentHandlerError)?;
        if proposal.is_reserved() {
            return Err(AgentHandlerError);
        }
        // First bring every already-committed Ordered base into the journal;
        // a Merge event may never synthesize or outrun that boundary.
        if let Ok(mut host) = self.host.lock() {
            drain_committed(&mut host, self.agent, &self.ordered_replies)
                .map_err(|_| AgentHandlerError)?;
        } else {
            return Err(AgentHandlerError);
        }

        let mut pending = heads;
        let mut seen = BTreeSet::new();
        let mut fetched = BTreeMap::<MergeEventId, MergeEvent>::new();
        let mut scanned_bytes = 0usize;
        let mut fetched_events = 0usize;
        let mut fetched_bytes = 0usize;
        let deadline = Instant::now() + MERGE_SYNC_BUDGET;
        while let Some(hash) = pending.pop() {
            if !seen.insert(hash) {
                continue;
            }
            if seen.len() > MAX_MERGE_SYNC_SCAN_EVENTS {
                return Err(AgentHandlerError);
            }
            let event_id = MergeEventId(hash.0);
            let local = self
                .host
                .lock()
                .map_err(|_| AgentHandlerError)?
                .merge_object(self.agent, event_id)
                .map_err(|_| AgentHandlerError)?;
            let needs_staging = merge_object_needs_staging(&local);
            let bytes = match local {
                SharedMergeObject::Published(_) => continue,
                SharedMergeObject::Staged(bytes) => bytes,
                SharedMergeObject::Missing => {
                    if fetched_events >= MAX_MERGE_SYNC_EVENTS {
                        break;
                    }
                    let Some(remaining) = deadline
                        .checked_duration_since(Instant::now())
                        .filter(|remaining| !remaining.is_zero())
                    else {
                        break;
                    };
                    let bytes = self
                        .network
                        .send_agent_merge_fetch_node(sender, self.route, hash)
                        .recv_timeout(remaining.min(AGENT_REQUEST_TIMEOUT))
                        .map_err(|_| AgentHandlerError)?
                        .map_err(|_| AgentHandlerError)?
                        .ok_or(AgentHandlerError)?;
                    let next_bytes = fetched_bytes
                        .checked_add(bytes.len())
                        .ok_or(AgentHandlerError)?;
                    // Leave this object missing and retry it in the next pump
                    // rather than exceeding a declared per-pass fetch budget.
                    // Already staged ancestors do not consume the next pass's
                    // network budget, so this still makes forward progress.
                    if next_bytes > MAX_MERGE_SYNC_BYTES {
                        break;
                    }
                    fetched_events += 1;
                    fetched_bytes = next_bytes;
                    bytes
                }
            };
            if bytes.is_empty() || bytes.len() > MAX_JOURNAL_RECORD_BYTES {
                return Err(AgentHandlerError);
            }
            scanned_bytes = scanned_bytes
                .checked_add(bytes.len())
                .filter(|total| *total <= MAX_REPLAY_SUFFIX_BYTES)
                .ok_or(AgentHandlerError)?;
            let event = MergeEvent::decode(&bytes).map_err(|_| AgentHandlerError)?;
            if event.id() != event_id || event.encode() != bytes {
                return Err(AgentHandlerError);
            }
            if needs_staging {
                self.host
                    .lock()
                    .map_err(|_| AgentHandlerError)?
                    .stage_merge(self.agent, &event)
                    .map_err(|_| AgentHandlerError)?;
            }
            pending.extend(event.parents.iter().map(|parent| Hash(*parent.as_bytes())));
            fetched.insert(event_id, event);
        }

        let mut ordered = fetched.into_values().collect::<Vec<_>>();
        ordered.sort_unstable_by_key(|event| (event.causal_height, event.id()));
        let mut host = self.host.lock().map_err(|_| AgentHandlerError)?;
        let mut imported_events = 0usize;
        let mut imported_bytes = 0usize;
        for event in ordered {
            if imported_events == MAX_MERGE_SYNC_EVENTS || Instant::now() >= deadline {
                break;
            }
            let mut parents_published = true;
            for parent in &event.parents {
                if !matches!(
                    host.merge_object(self.agent, *parent)
                        .map_err(|_| AgentHandlerError)?,
                    SharedMergeObject::Published(_)
                ) {
                    parents_published = false;
                    break;
                }
            }
            if !parents_published {
                continue;
            }
            let event_bytes = event.encode().len();
            let Some(next_bytes) = imported_bytes.checked_add(event_bytes) else {
                return Err(AgentHandlerError);
            };
            if next_bytes > MAX_MERGE_SYNC_BYTES {
                break;
            }
            match host
                .import_merge(self.agent, &event)
                .map_err(|_| AgentHandlerError)?
            {
                SharedAgentApplyOutcome::Applied { .. }
                | SharedAgentApplyOutcome::Duplicate { .. } => {}
                SharedAgentApplyOutcome::Idle => return Err(AgentHandlerError),
            }
            imported_events += 1;
            imported_bytes = next_bytes;
        }
        Ok(())
    }

    fn handle_merge(
        &self,
        sender: NodeId,
        message: MergeMessage,
    ) -> Result<AgentMessage, AgentHandlerError> {
        match message {
            MergeMessage::FetchHeads => self.local_merge_heads(),
            MergeMessage::AnnounceHeads(heads) => {
                self.sync_merge_heads(sender, heads)?;
                self.local_merge_heads()
            }
            MergeMessage::FetchNode(hash) => {
                let bytes = self
                    .host
                    .lock()
                    .map_err(|_| AgentHandlerError)?
                    .merge_node(self.agent, MergeEventId(hash.0))
                    .map_err(|_| AgentHandlerError)?;
                if let Some(bytes) = &bytes {
                    let event = MergeEvent::decode(bytes).map_err(|_| AgentHandlerError)?;
                    if event.id().as_bytes() != hash.as_bytes() || event.encode() != *bytes {
                        return Err(AgentHandlerError);
                    }
                }
                Ok(AgentMessage::Merge(MergeMessage::Node { hash, bytes }))
            }
            _ => Err(AgentHandlerError),
        }
    }
}

impl AgentRouteHandler for SharedRouteHandler {
    fn handle(&self, request: AuthenticatedAgentFrame) -> Result<AgentMessage, AgentHandlerError> {
        // Hold a shared generation lease through the complete bounded handler
        // call. Retirement takes the exclusive side before removing the route,
        // so a registration cloned by the network loop cannot mutate after
        // its exact generation has been revoked.
        let live = self.lifecycle.read().map_err(|_| AgentHandlerError)?;
        if !*live {
            return Err(AgentHandlerError);
        }
        let sender = request.sender();
        let frame = request.into_frame();
        if frame.route != self.route {
            return Err(AgentHandlerError);
        }
        #[cfg(test)]
        if self.raft_isolated.load(Ordering::Acquire)
            && matches!(&frame.message, AgentMessage::Raft(_))
        {
            return Err(AgentHandlerError);
        }
        match frame.message {
            AgentMessage::AuthorityReadBarrierRequest(request) => {
                let barrier = self
                    .authority_read_barrier(request, sender, ORDERED_REPLY_WAIT)
                    .ok();
                Ok(AgentMessage::AuthorityReadBarrierReply {
                    request: request.request,
                    barrier,
                })
            }
            #[cfg(target_os = "linux")]
            AgentMessage::ForwardedSharedInstallRequest(request) => {
                let correlation = request.correlation();
                let next_offset = self.handle_forwarded_shared_install(sender, &request).map_err(|error| {
                    if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                        let operation = match &request.operation {
                            super::agent_protocol::ForwardedSharedInstallOperation::Progress => "progress",
                            super::agent_protocol::ForwardedSharedInstallOperation::Chunk(_) => "chunk",
                            super::agent_protocol::ForwardedSharedInstallOperation::Finish => "finish",
                        };
                        tracing::debug!(operation, ?error, "Shared Install transfer peer refused");
                    }
                    error
                }).ok();
                Ok(AgentMessage::ForwardedSharedInstallReply {
                    request: correlation,
                    next_offset,
                })
            }
            AgentMessage::ManagementRecoveryCommandRequest(command) => {
                let commitment = Hash(command.commitment().0);
                let result = self.handle_management_metadata(sender, &command);
                #[cfg(test)]
                if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                    eprintln!(
                        "management_metadata_receive node={:?} sender={sender:?} result={result:?}",
                        self.network.agent_node_id()
                    );
                }
                let applied = result.is_ok();
                Ok(AgentMessage::ManagementRecoveryCommandReply {
                    command: commitment,
                    applied,
                })
            }
            AgentMessage::ManagementRecoveryOperationRequest(request) => {
                let correlation = request.correlation();
                let result = self.handle_management_operation(sender, &request);
                #[cfg(test)]
                if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                    eprintln!(
                        "management_operation_receive node={:?} sender={sender:?} member={:?} operation={:?} result={result:?}",
                        self.network.agent_node_id(),
                        request.member,
                        request.operation
                    );
                }
                let applied = result.is_ok();
                Ok(AgentMessage::ManagementRecoveryOperationReply {
                    request: correlation,
                    applied,
                })
            }
            AgentMessage::CommonSnapshotVoteRequest(claim) => {
                let commitment = Hash(claim.commitment().0);
                let started = Instant::now();
                let trace_phase = |phase: &str| {
                    tracing::debug!(
                        node = ?self.network.agent_node_id(),
                        agent = ?self.agent,
                        claim = ?commitment,
                        phase,
                        elapsed_us = started.elapsed().as_micros(),
                        "Common checkpoint vote phase"
                    );
                };
                trace_phase("handler_enter");
                let signature = (|| {
                    #[cfg(test)]
                    let trace_refusal = |reason: &str| {
                        if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                            eprintln!(
                                "common_vote early_refusal node={:?} reason={reason} expected={:?}",
                                self.network.agent_node_id(),
                                claim.commitment().0
                            );
                        }
                    };
                    let _proposal = self
                        .proposal
                        .try_lock()
                        .map_err(|error| {
                            #[cfg(test)]
                            trace_refusal(match error {
                                std::sync::TryLockError::WouldBlock => "proposal_busy",
                                std::sync::TryLockError::Poisoned(_) => "proposal_poisoned",
                            });
                            #[cfg(not(test))]
                            let _ = error;
                        })
                        .ok()?;
                    trace_phase("proposal_acquired");
                    let mut host = self
                        .host
                        .lock()
                        .map_err(|_| {
                            #[cfg(test)]
                            trace_refusal("host_poisoned");
                        })
                        .ok()?;
                    trace_phase("host_acquired");
                    drain_committed(&mut host, self.agent, &self.ordered_replies)
                        .map_err(|_| {
                            #[cfg(test)]
                            trace_refusal("drain_committed");
                        })
                        .ok()?;
                    trace_phase("committed_drained");
                    let status = host
                        .supervisor_attachment_status(self.agent)
                        .map_err(|_| {
                            #[cfg(test)]
                            trace_refusal("attachment_status");
                        })
                        .ok()?
                        .or_else(|| {
                            #[cfg(test)]
                            trace_refusal("missing_attachment");
                            None
                        })?;
                    let fingerprint = AttachmentFingerprint::from_attachment_status(&status)
                        .map_err(|_| {
                            #[cfg(test)]
                            trace_refusal("attachment_fingerprint");
                        })
                        .ok()?;
                    if status.transport != SharedAgentTransportState::Attached
                        || fingerprint.protocol_route != self.route
                        || fingerprint.next_committee.is_some()
                        || fingerprint.joint_old.is_some()
                        || fingerprint.voters.len() != 3
                        || fingerprint.voters.binary_search(&sender).is_err()
                        || fingerprint
                            .voters
                            .binary_search(&self.network.agent_node_id())
                            .is_err()
                    {
                        #[cfg(test)]
                        trace_refusal("attachment_scope");
                        return None;
                    }
                    trace_phase("attachment_verified");
                    let signed = host.sign_common_snapshot_candidate(self.agent, &claim);
                    tracing::debug!(
                        node = ?self.network.agent_node_id(),
                        agent = ?self.agent,
                        claim = ?commitment,
                        phase = "common_snapshot_signed",
                        elapsed_us = started.elapsed().as_micros(),
                        signed = signed.is_ok(),
                        "Common checkpoint vote phase"
                    );
                    #[cfg(test)]
                    if let Err(error) = &signed
                        && std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some()
                    {
                        eprintln!(
                            "common_vote local_refusal node={:?} error={error:?} expected={:?}",
                            self.network.agent_node_id(),
                            claim.commitment().0
                        );
                        match host.request_common_snapshot_compaction(self.agent) {
                            Ok(actual) => {
                                if let Ok(manifest) = host.recovery_manifest(self.agent) {
                                    trace_common_checkpoint_material_for_test(
                                        "refusing_voter",
                                        crate::service::NodeId(self.network.agent_node_id().0),
                                        actual.claim(),
                                        &manifest,
                                    );
                                }
                            }
                            Err(error) => eprintln!(
                                "common_vote local_candidate_error node={:?} error={error:?}",
                                self.network.agent_node_id()
                            ),
                        }
                    }
                    signed.ok()
                })();
                tracing::debug!(
                    node = ?self.network.agent_node_id(),
                    agent = ?self.agent,
                    claim = ?commitment,
                    phase = "reply_ready",
                    elapsed_us = started.elapsed().as_micros(),
                    signed = signature.is_some(),
                    "Common checkpoint vote phase"
                );
                Ok(AgentMessage::CommonSnapshotVoteReply {
                    claim: commitment,
                    signature,
                })
            }
            AgentMessage::CurrentAppliedAvailabilityRequest(request) => {
                let mut host = self.host.lock().map_err(|_| AgentHandlerError)?;
                let status = host
                    .supervisor_attachment_status(self.agent)
                    .map_err(|_| AgentHandlerError)?
                    .ok_or(AgentHandlerError)?;
                let fingerprint = AttachmentFingerprint::from_attachment_status(&status)
                    .map_err(|_| AgentHandlerError)?;
                let local = NodeId(host.scope().node.0);
                let current_voter = fingerprint.protocol_route == self.route
                    && fingerprint.next_committee.is_none()
                    && fingerprint.joint_old.is_none()
                    && fingerprint.voters.len() == 3
                    && fingerprint.voters.binary_search(&sender).is_ok()
                    && fingerprint.voters.binary_search(&local).is_ok();
                #[cfg(feature = "experimental-state-blocks")]
                let available = current_voter
                    && host
                        .verify_current_ordered_availability(
                            self.agent,
                            request.raft_index,
                            request.raft_term,
                            crate::service::Hash(request.claim.0),
                        )
                        .is_ok();
                #[cfg(not(feature = "experimental-state-blocks"))]
                let available = {
                    let _ = current_voter;
                    false
                };
                Ok(AgentMessage::CurrentAppliedAvailabilityReply { request, available })
            }
            AgentMessage::AppliedAvailabilityRequest(request) => {
                #[cfg(test)]
                let started = Instant::now();
                let mut host = self.host.lock().map_err(|_| AgentHandlerError)?;
                let status = host
                    .supervisor_attachment_status(self.agent)
                    .map_err(|_| AgentHandlerError)?
                    .ok_or(AgentHandlerError)?;
                let fingerprint = AttachmentFingerprint::from_attachment_status(&status)
                    .map_err(|_| AgentHandlerError)?;
                let local = NodeId(host.scope().node.0);
                let available = fingerprint.protocol_route == self.route
                    && fingerprint.next_committee.is_none()
                    && fingerprint.joint_old.is_none()
                    && matches!(fingerprint.voters.len(), 1 | 3)
                    && fingerprint.voters.binary_search(&sender).is_ok()
                    && fingerprint.voters.binary_search(&local).is_ok()
                    && host.verify_ordered_availability(
                        self.agent, request.raft_index, request.raft_term,
                        crate::service::Hash(request.claim.0),
                    ).map_err(|error| {
                        #[cfg(test)]
                        if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                            eprintln!("availability_remote node={local:?} raft={}/{} claim={:?} error={error:?} elapsed_us={}", request.raft_index, request.raft_term, request.claim, started.elapsed().as_micros());
                        }
                        #[cfg(not(test))]
                        let _ = error;
                    }).is_ok();
                #[cfg(test)]
                if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                    eprintln!(
                        "availability_remote node={local:?} raft={}/{} claim={:?} available={available} elapsed_us={}",
                        request.raft_index,
                        request.raft_term,
                        request.claim,
                        started.elapsed().as_micros()
                    );
                }
                Ok(AgentMessage::AppliedAvailabilityReply { request, available })
            }
            AgentMessage::InvokeRequest(request) => self.handle_invocation(sender, request),
            AgentMessage::Raft(message) => self.handle_raft(sender, message),
            AgentMessage::Merge(message) => self.handle_merge(sender, message),
            _ => Err(AgentHandlerError),
        }
    }
}

struct AttachedGeneration {
    fingerprint: AttachmentFingerprint,
    handler: Arc<dyn AgentRouteHandler>,
    coordinator: Arc<SharedRouteHandler>,
    worker: Option<vos_raft::Worker<NodeId>>,
    apply_thread: Option<JoinHandle<()>>,
    merge_stop: Arc<AtomicBool>,
    merge_thread: Option<JoinHandle<()>>,
    stale: Arc<AtomicBool>,
    lifecycle: Arc<RwLock<bool>>,
}

struct SharedGenerationAccess<'a> {
    coordinator: &'a SharedRouteHandler,
    fingerprint: &'a AttachmentFingerprint,
    stale: &'a AtomicBool,
}

/// Non-owning, exact-generation access for an ordinary supervisor route.
/// Closed handles cannot retain the physical host or network worker. Each
/// operation upgrades the coordinator and takes its generation lifecycle lease.
#[derive(Clone)]
pub(crate) struct SharedAgentRouteHandle {
    coordinator: std::sync::Weak<SharedRouteHandler>,
    fingerprint: AttachmentFingerprint,
    stale: Arc<AtomicBool>,
}

impl SharedAgentRouteHandle {
    pub(crate) fn agent(&self) -> vos_agent_sdk::AgentId {
        vos_agent_sdk::AgentId(self.fingerprint.durable_route.agent().0)
    }

    pub(crate) fn same_generation(&self, other: &Self) -> bool {
        self.coordinator.ptr_eq(&other.coordinator) && self.fingerprint == other.fingerprint
    }

    fn with_generation<T>(
        &self,
        operation: impl FnOnce(
            &SharedAgentHost,
            crate::service::AgentId,
            &crate::agent::shared_host::SharedAgentAttachmentStatus,
        ) -> Result<T, SharedAgentHostError>,
    ) -> Result<T, SharedAgentHostError> {
        let coordinator = self
            .coordinator
            .upgrade()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = coordinator
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || self.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let host = coordinator
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let status = host
            .supervisor_attachment_status(coordinator.agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if status.transport != SharedAgentTransportState::Attached
            || AttachmentFingerprint::from_attachment_status(&status)? != self.fingerprint
        {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let result = operation(&host, coordinator.agent, &status)?;
        if self.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        Ok(result)
    }

    pub(crate) fn projection(&self) -> Result<SharedAgentRuntimeProjection, SharedAgentHostError> {
        self.with_generation(|host, agent, status| {
            let projection = host.clean_runtime_projection(agent)?;
            if !projection_matches_attachment_status(&projection, status) {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            Ok(projection)
        })
    }

    pub(crate) fn material(
        &self,
        actor: vos_agent_sdk::ActorId,
    ) -> Result<
        crate::agent::invocation_preparation::PhysicalInvocationMaterial,
        SharedAgentHostError,
    > {
        self.with_generation(|host, agent, status| {
            let material = host.supervisor_invocation_material(agent, actor)?;
            let projection = SharedAgentRuntimeProjection {
                descriptor: material.descriptor.clone(),
                actors: vec![material.actor.clone()],
            };
            if !projection_matches_attachment_status(&projection, status) {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            Ok(material)
        })
    }

    pub(crate) fn execute(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        request: crate::agent::shared_journal_driver::CleanInvocationReplayRequest,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        use crate::agent::shared_journal_driver::CleanInvocationReplayRequest;
        if matches!(
            &request,
            CleanInvocationReplayRequest::Invoke { context, .. }
                | CleanInvocationReplayRequest::Resume { context, .. }
                if !context.is_direct()
        ) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let coordinator = self
            .coordinator
            .upgrade()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        SharedAgentNetworkHost::execute_generation(
            SharedGenerationAccess {
                coordinator: &coordinator,
                fingerprint: &self.fingerprint,
                stale: &self.stale,
            },
            expected,
            request,
            false,
            SupervisorAdmission::Ordinary,
        )
    }

    pub(crate) fn audit(
        &self,
        head: crate::agent_sdk::authority::AuthorityProjectionHead,
        projected: &[crate::agent::supervisor_adapters::AgentAuthorityRouteProjection],
    ) -> Result<crate::agent::shared_host::SharedAuthorityProjectionAudit, SharedAgentHostError>
    {
        self.with_generation(|host, agent, _| {
            host.audit_agent_authority_projection(agent, head, projected)
        })
    }
}

fn acquire_route_activation<'a>(
    lifecycle: &'a RwLock<bool>,
    stale: &AtomicBool,
) -> Option<std::sync::RwLockReadGuard<'a, bool>> {
    let live = lifecycle.read().ok()?;
    if !*live || stale.load(Ordering::Acquire) {
        // Return only after the rejected read lease has left scope. Cleanup
        // takes the exclusive side and must never self-deadlock on this guard.
        return None;
    }
    Some(live)
}

fn retire_route_with_lease(
    network: &Network,
    route: AgentGenerationRoute,
    handler: &Arc<dyn AgentRouteHandler>,
    lifecycle: &RwLock<bool>,
) {
    // Remove the directory entry first so the finite ingress permit set is a
    // hard upper bound on registrations which could already have cloned this
    // owner. Then take the exclusive lease and drain those in-flight calls.
    network.retire_agent_route(route, handler);
    let mut live = lifecycle
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *live = false;
    // Attachment activation holds a read lease while publishing its route.
    // If this retirement raced that activation, the first removal may have
    // happened before the route existed. Once the exclusive lease is ours,
    // activation has finished and a second pointer-qualified removal closes
    // that race without reopening ingress starvation.
    network.retire_agent_route(route, handler);
}

/// Owning live attachment for every generation currently opened by a Shared
/// host. Dropping it retires exact route owners before stopping workers.
pub struct SharedAgentNetworkHost {
    host: Arc<Mutex<SharedAgentHost>>,
    network: Arc<Network>,
    generations: BTreeMap<crate::service::AgentId, AttachedGeneration>,
    // Retain system identity across refresh/checkpoint reattachment so the
    // applicable promotion and recovery barriers still guard route exposure.
    // Audited stable-three followers may register before leader promotion.
    system_agents: BTreeSet<crate::service::AgentId>,
    // Exact pending envelopes outlive a volatile route/worker generation.
    // Startup callers must seed these from independently verified durable
    // lifecycle stores before any system route is activated.
    management_retirements:
        BTreeMap<crate::service::AgentId, Vec<[crate::agent_sdk::RuntimeWork; 2]>>,
    management_pending: BTreeMap<crate::service::AgentId, Vec<PendingManagement>>,
    #[cfg(test)]
    fail_reattach_once: bool,
}

/// Reserves the host's storage boundary before any worker database handle,
/// route, or background thread is created. Failed setup releases the
/// `Attaching` state only after all later-declared resources have dropped.
struct TransportAttachReservation {
    host: Arc<Mutex<SharedAgentHost>>,
    agent: crate::service::AgentId,
    armed: bool,
}

impl TransportAttachReservation {
    fn reserve(
        host: Arc<Mutex<SharedAgentHost>>,
        agent: crate::service::AgentId,
    ) -> Result<Self, SharedAgentHostError> {
        host.lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .reserve_transport_attachment(agent)?;
        Ok(Self {
            host,
            agent,
            armed: true,
        })
    }

    fn mark_attached(&mut self) -> Result<(), SharedAgentHostError> {
        self.host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .mark_transport_attached(self.agent)?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for TransportAttachReservation {
    fn drop(&mut self) {
        if self.armed {
            if let Ok(mut host) = self.host.lock() {
                let _ = host.release_transport_attachment(self.agent);
            }
        }
    }
}

impl SharedAgentNetworkHost {
    /// Isolate only the actual Raft transport; keep the live owner, worker,
    /// admission keys and authenticated application RPCs for election tests.
    #[cfg(test)]
    pub(crate) fn set_raft_isolated_for_test(
        &self,
        agent: crate::service::AgentId,
        isolated: bool,
    ) -> Result<(), SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        attached
            .coordinator
            .raft_isolated
            .store(isolated, Ordering::Release);
        Ok(())
    }

    pub(crate) fn management_recovery_manifest(
        &self,
        agent: crate::service::AgentId,
    ) -> Result<SharedRecoveryManifest, SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, agent, &attached.coordinator.ordered_replies)?;
        host.recovery_manifest(agent)
    }

    pub fn attach(
        host: Arc<Mutex<SharedAgentHost>>,
        network: Arc<Network>,
    ) -> Result<Self, SharedAgentHostError> {
        Self::attach_internal(host, network, None, None, None)
    }

    /// Retain consensus transport while a fixed-roster system bootstrap waits
    /// for election. No serving owner exists at this stage. Ordinary recovered
    /// generations must continue through their admission-aware attachment path.
    pub(crate) fn attach_pending_system(
        host: Arc<Mutex<SharedAgentHost>>,
        network: Arc<Network>,
        agent: crate::service::AgentId,
    ) -> Result<Self, SharedAgentHostError> {
        let statuses = host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .list()?;
        if statuses.len() != 1 || statuses[0].generation.agent() != agent {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        // The synchronous promotion barrier cannot run until peers can reach
        // our registered route. Pending completion checks it after attachment.
        let mut attachment = Self::attach_internal(host, network, None, None, None)?;
        attachment.system_agents.insert(agent);
        Ok(attachment)
    }

    /// Attach a clean system Agent. With no durable pending management,
    /// checkpoint before a mandatory leader no-op could combine
    /// with one retained uncommitted physical row and overrun the evidence
    /// suffix. Snapshot installation preserves that tail but resets its
    /// authenticated capacity domain at the applied boundary.
    pub(crate) fn attach_system(
        host: Arc<Mutex<SharedAgentHost>>,
        network: Arc<Network>,
        agent: crate::service::AgentId,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
    ) -> Result<Self, SharedAgentHostError> {
        let needs_checkpoint = host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .show(agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .remaining_slots
            <= 1;
        if needs_checkpoint {
            let mut locked = host.lock().map_err(|_| SharedAgentHostError::Unavailable)?;
            Self::install_detached_checkpoint(&mut locked, agent, expected_committee, signer)?;
        }
        Self::attach_internal(host, network, Some(agent), None, None)
    }

    /// Restore an independently verified pending retirement before publishing
    /// the system route. Do not checkpoint away missing
    /// Linear invocation/acknowledgement evidence to make this attachment fit.
    pub(crate) fn attach_recovering_management_retirement(
        host: Arc<Mutex<SharedAgentHost>>,
        network: Arc<Network>,
        agent: crate::service::AgentId,
        envelopes: [crate::agent_sdk::RuntimeWork; 2],
    ) -> Result<Self, SharedAgentHostError> {
        Self::attach_recovering_management_retirement_set(host, network, agent, vec![envelopes])
    }

    /// All pairs must come from independently verified durable intents. Keep
    /// the whole set reserved before publishing any worker route; completing
    /// one pair must not expose capacity retained for another pending intent.
    pub(crate) fn attach_recovering_management_retirement_set(
        host: Arc<Mutex<SharedAgentHost>>,
        network: Arc<Network>,
        agent: crate::service::AgentId,
        pairs: Vec<[crate::agent_sdk::RuntimeWork; 2]>,
    ) -> Result<Self, SharedAgentHostError> {
        if pairs.is_empty() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        Self::attach_recovering_management_set(host, network, agent, vec![], pairs)
    }

    /// The caller must independently verify the durable intent set and its
    /// pre-dispatch anchors before supplying it. This publishes no unguarded
    /// generation between attachment and exact pending-work recovery.
    pub(crate) fn attach_recovering_management_pending(
        host: Arc<Mutex<SharedAgentHost>>,
        network: Arc<Network>,
        agent: crate::service::AgentId,
        pending: Vec<PendingManagement>,
    ) -> Result<Self, SharedAgentHostError> {
        pending_management_keys(agent, &pending)?;
        Self::attach_recovering_management_set(host, network, agent, pending, vec![])
    }

    /// Seed both independently verified recovery classes before route
    /// publication. No identity may belong to both admission classes.
    pub(crate) fn attach_recovering_management_set(
        host: Arc<Mutex<SharedAgentHost>>,
        network: Arc<Network>,
        agent: crate::service::AgentId,
        pending: Vec<PendingManagement>,
        retiring: Vec<[crate::agent_sdk::RuntimeWork; 2]>,
    ) -> Result<Self, SharedAgentHostError> {
        Self::attach_recovering_management_inputs(host, network, agent, pending, retiring)
    }

    fn attach_recovering_management_inputs(
        host: Arc<Mutex<SharedAgentHost>>,
        network: Arc<Network>,
        agent: crate::service::AgentId,
        pending: Vec<PendingManagement>,
        retiring: Vec<[crate::agent_sdk::RuntimeWork; 2]>,
    ) -> Result<Self, SharedAgentHostError> {
        if pending.is_empty() && retiring.is_empty() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let mut seen = BTreeSet::new();
        if !pending.is_empty() {
            for (key, _) in pending_management_keys(agent, &pending)? {
                seen.insert(key.invocation);
            }
        }
        if !retiring.is_empty() {
            for key in management_retirement_set_keys(agent, &retirement_pair_refs(&retiring))?
                .into_iter()
                .flatten()
            {
                if !seen.insert(key.invocation) {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
            }
        }
        if seen.len() > MAX_REPLAY_SUFFIX_ENTRIES {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        Self::attach_internal(
            host,
            network,
            Some(agent),
            (!retiring.is_empty()).then_some((agent, retiring)),
            (!pending.is_empty()).then_some((agent, pending)),
        )
    }

    fn attach_internal(
        host: Arc<Mutex<SharedAgentHost>>,
        network: Arc<Network>,
        promotion_barrier: Option<crate::service::AgentId>,
        retirement: Option<(
            crate::service::AgentId,
            Vec<[crate::agent_sdk::RuntimeWork; 2]>,
        )>,
        pending: Option<(crate::service::AgentId, Vec<PendingManagement>)>,
    ) -> Result<Self, SharedAgentHostError> {
        let statuses = host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .list()?;
        let mut attachment = Self {
            host,
            network,
            generations: BTreeMap::new(),
            system_agents: promotion_barrier.into_iter().collect(),
            management_retirements: retirement.into_iter().collect(),
            management_pending: pending.into_iter().collect(),
            #[cfg(test)]
            fail_reattach_once: false,
        };
        for status in statuses {
            if status.local_role.is_some() {
                let barrier = promotion_barrier == Some(status.generation.agent())
                    && !attachment
                        .management_pending
                        .contains_key(&status.generation.agent())
                    && !attachment
                        .management_retirements
                        .contains_key(&status.generation.agent());
                attachment.attach_status(status, barrier)?;
            }
        }
        if attachment
            .management_retirements
            .keys()
            .chain(attachment.management_pending.keys())
            .any(|agent| !attachment.generations.contains_key(agent))
        {
            return Err(SharedAgentHostError::AgentNotFound);
        }
        Ok(attachment)
    }

    fn install_detached_checkpoint(
        host: &mut SharedAgentHost,
        agent: crate::service::AgentId,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
    ) -> Result<(), SharedAgentHostError> {
        if expected_committee.members().len() != 1
            || expected_committee.voter_count() != 1
            || expected_committee
                .member_by_node(signer.node())
                .is_none_or(|member| member.replica().role != ReplicaRole::Voter)
        {
            return Err(SharedAgentHostError::SnapshotCertificateInvalid);
        }
        let candidate = host.request_snapshot_compaction(agent)?;
        if candidate.claim().active_committee() != expected_committee {
            return Err(SharedAgentHostError::SnapshotCertificateInvalid);
        }
        let signature = signer
            .sign_snapshot_candidate(&candidate)
            .ok_or(SharedAgentHostError::SnapshotCertificateInvalid)?;
        let certificate =
            SharedAgentSnapshotCertificate::new(candidate.claim().clone(), vec![signature])
                .map_err(|_| SharedAgentHostError::SnapshotCertificateInvalid)?;
        host.install_snapshot(agent, &certificate)?;

        Ok(())
    }

    /// Repair a missing/stale live transport attachment from durable host
    /// status before any management capacity decision. This also closes the
    /// same-process retry edge after snapshot installation succeeded but its
    /// first reattachment attempt failed.
    pub(crate) fn ensure_reattached(
        &mut self,
        agent: crate::service::AgentId,
    ) -> Result<(), SharedAgentHostError> {
        self.refresh()?;
        self.generations
            .contains_key(&agent)
            .then_some(())
            .ok_or(SharedAgentHostError::TransportNotAttached)
    }

    pub(crate) fn reserve_management_retirement(
        &mut self,
        agent: crate::service::AgentId,
        envelopes: [&crate::agent_sdk::RuntimeWork; 2],
    ) -> Result<(), SharedAgentHostError> {
        self.reserve_management_retirement_set(agent, &[envelopes])
    }

    pub(crate) fn record_management_anchor<F, T>(
        &self,
        agent: crate::service::AgentId,
        envelope: &crate::agent_sdk::RuntimeWork,
        record: F,
    ) -> Result<T, SharedAgentHostError>
    where
        F: FnOnce(
            crate::agent::clean_management_intent::ManagementJournalAnchor,
        ) -> Result<T, SharedAgentHostError>,
    {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        attached
            .coordinator
            .record_management_anchor(envelope, record)
    }

    /// The caller must authenticate the phase transition and pledge the exact
    /// returned envelope/anchor, including when retrying an ambiguous commit.
    pub(crate) fn extend_management_pending<F, T>(
        &mut self,
        agent: crate::service::AgentId,
        predecessor: &PendingManagement,
        proposed: &crate::agent_sdk::RuntimeWork,
        record: F,
    ) -> Result<T, SharedAgentHostError>
    where
        F: FnOnce(&PendingManagement) -> Result<T, SharedAgentHostError>,
    {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let pending = self
            .management_pending
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::Conflict)?;
        attached.coordinator.extend_management_pending(
            pending,
            self.management_retirements
                .get(&agent)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
            Some(predecessor),
            self.system_agents.contains(&agent),
            false,
            None,
            proposed,
            record,
        )
    }

    /// Scheduling hint only: never authorizes work or releases exclusion.
    /// Include retained attachment state as well as the active coordinator so
    /// refresh/recovery cannot briefly advertise a free management lane.
    pub(crate) fn management_admission_held(
        &self,
        agent: crate::service::AgentId,
    ) -> Result<bool, SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::Unavailable)?;
        let proposal = attached
            .coordinator
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if self.management_pending.contains_key(&agent)
            || self.management_retirements.contains_key(&agent)
            || proposal.management_pending.is_some()
            || proposal.management_retirement.is_some()
        {
            return Ok(true);
        }
        // Maintenance only: authenticate the applied replicated custody too.
        // A remote owner can hold this lane without any local intent map.
        // Admission still rechecks the fresh prefix after this scheduling hint.
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        Ok(host.recovery_manifest(agent)?.has_pending_management())
    }

    /// Reserve the initial immutable envelope and its journal anchor before
    /// publishing the intent. Retain admission after an ambiguous store error;
    /// an exact retry receives the original clock and anchor. This reserves the
    /// authorization/ACK plus a conservative bounded finalization/ACK delta.
    pub(crate) fn capture_management_pending<F, T>(
        &mut self,
        agent: crate::service::AgentId,
        proposed: &crate::agent_sdk::RuntimeWork,
        record: F,
    ) -> Result<T, SharedAgentHostError>
    where
        F: FnOnce(&PendingManagement) -> Result<T, SharedAgentHostError>,
    {
        self.capture_management_pending_guarded(agent, proposed, false, None, record)
    }

    fn capture_management_pending_guarded<F, T>(
        &mut self,
        agent: crate::service::AgentId,
        proposed: &crate::agent_sdk::RuntimeWork,
        fresh_only: bool,
        before_publication: Option<&mut ManagementPublicationGuard<'_>>,
        record: F,
    ) -> Result<T, SharedAgentHostError>
    where
        F: FnOnce(&PendingManagement) -> Result<T, SharedAgentHostError>,
    {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let pending = self.management_pending.entry(agent).or_default();
        let result = attached.coordinator.extend_management_pending(
            pending,
            self.management_retirements
                .get(&agent)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
            None,
            self.system_agents.contains(&agent),
            fresh_only,
            before_publication,
            proposed,
            record,
        );
        // Admission failures before reservation must not leave an empty root
        // refresh record. Callback failures keep the nonempty candidate.
        if pending.is_empty() {
            self.management_pending.remove(&agent);
        }
        result
    }

    /// Repair capacity only before a fresh management reservation exists.
    /// The full capture check decides whether compaction is needed and
    /// rechecks its exact budget afterwards.
    pub(crate) fn capture_management_pending_with_checkpoint<F, T>(
        &mut self,
        agent: crate::service::AgentId,
        proposed: &crate::agent_sdk::RuntimeWork,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
        record: F,
    ) -> Result<T, SharedAgentHostError>
    where
        F: FnOnce(&PendingManagement) -> Result<T, SharedAgentHostError>,
    {
        self.capture_management_pending_with_checkpoint_guarded(
            agent, proposed, expected_committee, signer, false, |_, _, _, _, _| Ok(()), record,
        )
    }

    /// A native preparation may establish same-open proof only while this
    /// guarded capture is about to publish a genuinely fresh original root.
    /// Existing capture/extension callers keep their unchanged retry behavior.
    pub(crate) fn capture_fresh_management_pending_with_checkpoint<F, V, T>(
        &mut self,
        agent: crate::service::AgentId,
        proposed: &crate::agent_sdk::RuntimeWork,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
        before_publication: V,
        record: F,
    ) -> Result<T, SharedAgentHostError>
    where
        F: FnOnce(&PendingManagement) -> Result<T, SharedAgentHostError>,
        V: FnMut(&PendingManagement, Option<&crate::agent::shared_recovery::management::SharedManagementRecoverySlot>, &[PendingManagement], &[[crate::agent_sdk::RuntimeWork; 2]], bool) -> Result<(), SharedAgentHostError>,
    {
        self.capture_management_pending_with_checkpoint_guarded(
            agent, proposed, expected_committee, signer, true, before_publication, record,
        )
    }

    /// A marked retry keeps its original anchor and validates the complete
    /// current family under the same guards before any metadata or WAL write.
    /// Capacity repair is no longer permitted after first publication proof.
    pub(crate) fn recapture_management_pending<F, V, T>(
        &mut self,
        agent: crate::service::AgentId,
        proposed: &crate::agent_sdk::RuntimeWork,
        mut before_publication: V,
        record: F,
    ) -> Result<T, SharedAgentHostError>
    where
        F: FnOnce(&PendingManagement) -> Result<T, SharedAgentHostError>,
        V: FnMut(&PendingManagement, Option<&crate::agent::shared_recovery::management::SharedManagementRecoverySlot>, &[PendingManagement], &[[crate::agent_sdk::RuntimeWork; 2]], bool) -> Result<(), SharedAgentHostError>,
    {
        self.ensure_reattached(agent)?;
        self.capture_management_pending_guarded(agent, proposed, false, Some(&mut before_publication), record)
    }

    fn capture_management_pending_with_checkpoint_guarded<F, V, T>(
        &mut self,
        agent: crate::service::AgentId,
        proposed: &crate::agent_sdk::RuntimeWork,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
        fresh_only: bool,
        mut before_publication: V,
        record: F,
    ) -> Result<T, SharedAgentHostError>
    where
        F: FnOnce(&PendingManagement) -> Result<T, SharedAgentHostError>,
        V: FnMut(&PendingManagement, Option<&crate::agent::shared_recovery::management::SharedManagementRecoverySlot>, &[PendingManagement], &[[crate::agent_sdk::RuntimeWork; 2]], bool) -> Result<(), SharedAgentHostError>,
    {
        self.ensure_reattached(agent)?;
        let mut record = Some(record);
        let publication_attempted = core::cell::Cell::new(false);
        let mut publication_guard = |pending: &PendingManagement, slot: Option<&crate::agent::shared_recovery::management::SharedManagementRecoverySlot>, previous: &[PendingManagement], retiring: &[[crate::agent_sdk::RuntimeWork; 2]], fixed_three| {
            publication_attempted.set(true);
            before_publication(pending, slot, previous, retiring, fixed_three)
        };
        let result = self.capture_management_pending_guarded(agent, proposed, fresh_only, if fresh_only { Some(&mut publication_guard) } else { None }, |pending| {
            record.take().expect("capture callback runs once")(pending)
        });
        if !matches!(result, Err(SharedAgentHostError::CapacityExhausted))
            || record.is_none()
            || publication_attempted.get()
            || self.management_pending.contains_key(&agent)
            || self.management_retirements.contains_key(&agent)
        {
            // A callback error (even CapacityExhausted) is publication
            // ambiguity, never permission to compact or retry the callback.
            return result;
        }
        let crate::agent_sdk::RuntimeWork::Invoke {
            invocation,
            authorization,
            ..
        } = proposed
        else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        self.certified_checkpoint_for_admission(
            agent,
            invocation,
            authorization,
            expected_committee,
            signer,
        )?;
        self.capture_management_pending_guarded(
            agent, proposed, fresh_only, if fresh_only { Some(&mut publication_guard) } else { None }, record.expect("unpublished callback"),
        )
    }

    /// Native terminal bridge only. The caller pledges successful durable
    /// lifecycle completion; this commits the exact signed retained scope's
    /// release and never derives completion from an ACK or missing intent.
    pub(crate) fn release_management_retention(
        &self,
        agent: crate::service::AgentId,
        root: &crate::agent_sdk::RuntimeWork,
    ) -> Result<(), SharedAgentHostError> {
        if !self.system_agents.contains(&agent) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        attached.coordinator.release_management_retention(root)
    }

    /// Inspect this open attachment's already held exact member without
    /// adopting registrations or restoring volatile exclusion.
    pub(crate) fn current_management_pending(
        &self,
        agent: crate::service::AgentId,
        invocation: crate::agent_sdk::InvocationId,
    ) -> Result<Option<PendingManagement>, SharedAgentHostError> {
        let found = self
            .management_pending
            .get(&agent)
            .and_then(|pending| {
                pending.iter().find(|(_, envelope)| {
                    matches!(envelope, crate::agent_sdk::RuntimeWork::Invoke { invocation: work, .. }
                        if work.invocation == invocation)
                })
            })
            .cloned();
        if let Some((anchor, envelope)) = &found {
            self.ensure_management_pending_member(agent, anchor, envelope)?;
        }
        Ok(found)
    }

    /// Recover a failed publication, including registration committed before
    /// the origin wrote its independent WAL. Only the actual owner's verified
    /// exact member may restore volatile exclusion; absence is not completion.
    pub(crate) fn retained_management_pending(
        &mut self,
        agent: crate::service::AgentId,
        invocation: crate::agent_sdk::InvocationId,
    ) -> Result<Option<PendingManagement>, SharedAgentHostError> {
        if let Some(found) = self.current_management_pending(agent, invocation)? {
            return Ok(Some(found));
        }
        self.retained_management_pending_with_validation(agent, invocation, |_, _, _| Ok(()))
    }

    /// Validate the complete applied family under the existing lifecycle,
    /// proposal and host guards before restoring its volatile reservation.
    /// The validator is pure and must not re-enter the host or coordinator.
    pub(crate) fn retained_management_pending_with_validation<F>(
        &mut self,
        agent: crate::service::AgentId,
        invocation: crate::agent_sdk::InvocationId,
        validate: F,
    ) -> Result<Option<PendingManagement>, SharedAgentHostError>
    where
        F: FnOnce(
            &crate::agent::shared_recovery::management::SharedManagementRecoverySlot,
            &[PendingManagement],
            &[[crate::agent_sdk::RuntimeWork; 2]],
        ) -> Result<(), SharedAgentHostError>,
    {
        if !self.system_agents.contains(&agent) {
            return Ok(None);
        }
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let mut proposal = attached
            .coordinator
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, agent, &attached.coordinator.ordered_replies)?;
        let status = host
            .supervisor_attachment_status(agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if AttachmentFingerprint::from_attachment_status(&status)?
            .members
            .len()
            == 1
        {
            // No replicated registration exists on the historical singleton
            // lane. The default wrapper preserves its existing volatile lookup.
            return Ok(None);
        }
        let manifest = host.recovery_manifest(agent)?;
        let Some(slot) = manifest
            .management_slot(crate::service::NodeId(self.network.agent_node_id().0))
        else {
            return Ok(None);
        };
        let previous = self
            .management_pending
            .get(&agent)
            .cloned()
            .unwrap_or_default();
        let previous_keys = if previous.is_empty() {
            None
        } else {
            Some(pending_management_keys(agent, &previous)?)
        };
        if proposal.checkpoint_gate.is_some()
            || proposal.management_retirement.is_some()
            || proposal.management_pending != previous_keys
        {
            return Err(SharedAgentHostError::Conflict);
        }
        validate(
            slot,
            &previous,
            self.management_retirements
                .get(&agent)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
        )?;
        if slot.is_released() {
            return Ok(None);
        }
        let Some(member) = slot
            .members()
            .iter()
            .find(|member| member.work().invocation == invocation)
        else {
            return Ok(None);
        };
        let found = (member.anchor().clone(), member.envelope().clone());
        if let Some(existing) = previous.iter().find(|(_, envelope)| {
            matches!(envelope, crate::agent_sdk::RuntimeWork::Invoke { invocation: work, .. }
                if work.invocation == invocation)
        }) {
            if existing != &found {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            return Ok(Some(found));
        }
        let mut pending = previous;
        pending.push(found.clone());
        proposal.management_pending = Some(pending_management_keys(agent, &pending)?);
        self.management_pending.insert(agent, pending);
        Ok(Some(found))
    }

    /// Publish signed terminal retirement before releasing its exact pending
    /// member. A failed store callback retains both admission and refresh state.
    /// Completed signed records may release after pruning without replaying.
    pub(crate) fn finish_pending_management_result<F>(
        &mut self,
        agent: crate::service::AgentId,
        anchor: &crate::agent::clean_management_intent::ManagementJournalAnchor,
        envelope: &crate::agent_sdk::RuntimeWork,
        completed: bool,
        complete: F,
    ) -> Result<(), SharedAgentHostError>
    where
        F: FnOnce() -> Result<(), SharedAgentHostError>,
    {
        let key = (management_envelope_key(agent, envelope)?, anchor.clone());
        let Some(pending) = self.management_pending.get(&agent) else {
            return if completed {
                Ok(())
            } else {
                Err(SharedAgentHostError::Conflict)
            };
        };
        let keys = pending_management_keys(agent, pending)?;
        if !keys.contains(&key) {
            return if completed {
                Ok(())
            } else {
                Err(SharedAgentHostError::Conflict)
            };
        }
        let remaining: Vec<_> = pending
            .iter()
            .zip(&keys)
            .filter(|(_, old)| **old != key)
            .map(|(entry, _)| entry.clone())
            .collect();
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let mut proposal = attached
            .coordinator
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if proposal.management_pending.as_ref() != Some(&keys) {
            return Err(SharedAgentHostError::Conflict);
        }
        if !completed {
            let crate::agent_sdk::RuntimeWork::Invoke {
                invocation,
                authorization,
                ..
            } = envelope
            else {
                return Err(SharedAgentHostError::ScopeMismatch);
            };
            let host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            if !host.retained_positive_clean_acknowledgement(agent, invocation, authorization)? {
                return Err(SharedAgentHostError::Conflict);
            }
            // Keep host and proposal locks across the independent store write.
            complete()?;
        } else {
            complete()?;
        }
        proposal.management_pending = if remaining.is_empty() {
            None
        } else {
            Some(pending_management_keys(agent, &remaining)?)
        };
        if remaining.is_empty() {
            self.management_pending.remove(&agent);
        } else {
            self.management_pending.insert(agent, remaining);
        }
        Ok(())
    }

    /// A saved live intent may resume only under its exact restored reservation.
    /// Possession of an old envelope is not permission to dispatch unprotected.
    pub(crate) fn ensure_management_pending_member(
        &self,
        agent: crate::service::AgentId,
        anchor: &crate::agent::clean_management_intent::ManagementJournalAnchor,
        envelope: &crate::agent_sdk::RuntimeWork,
    ) -> Result<(), SharedAgentHostError> {
        let key = management_envelope_key(agent, envelope)?;
        let pending = self
            .management_pending
            .get(&agent)
            .ok_or(SharedAgentHostError::Conflict)?;
        let keys = pending_management_keys(agent, pending)?;
        if !keys.contains(&(key, anchor.clone())) {
            return Err(SharedAgentHostError::Conflict);
        }
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let proposal = attached
            .coordinator
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if proposal.management_pending.as_ref() != Some(&keys) {
            return Err(SharedAgentHostError::Conflict);
        }
        Ok(())
    }

    pub(crate) fn reserve_management_retirement_set(
        &mut self,
        agent: crate::service::AgentId,
        pairs: &[[&crate::agent_sdk::RuntimeWork; 2]],
    ) -> Result<(), SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        attached
            .coordinator
            .reserve_management_retirement_set(pairs)?;
        self.management_retirements.entry(agent).or_insert_with(|| {
            pairs
                .iter()
                .map(|pair| [pair[0].clone(), pair[1].clone()])
                .collect()
        });
        Ok(())
    }

    /// Transfer finished pairs from the verified pending set without opening admission
    /// between invocation recovery and positive-acknowledgement retirement.
    /// Preserve existing retirement pairs and every remaining anchored pending
    /// envelope; supply only newly finished pairs, which may be a strict subset.
    pub(crate) fn handoff_management_pending_to_retirement(
        &mut self,
        agent: crate::service::AgentId,
        pairs: &[[&crate::agent_sdk::RuntimeWork; 2]],
    ) -> Result<(), SharedAgentHostError> {
        let moved = management_retirement_set_keys(agent, pairs)?;
        // A failed retirement-store publication may already have completed
        // handoff. Revalidate the exact existing pair without duplicating it.
        if self
            .management_retirements
            .get(&agent)
            .is_some_and(|existing| {
                management_retirement_set_keys(agent, &retirement_pair_refs(existing))
                    .is_ok_and(|keys| moved.iter().all(|pair| keys.contains(pair)))
            })
        {
            return self.reserve_management_retirement_set(agent, pairs);
        }
        let pending = self
            .management_pending
            .get(&agent)
            .ok_or(SharedAgentHostError::Conflict)?;
        let pending_keys = pending_management_keys(agent, pending)?;
        let remaining: Vec<_> = pending
            .iter()
            .zip(pending_keys.iter())
            .filter(|(_, (key, _))| !moved.iter().flatten().any(|expected| expected == key))
            .map(|(entry, _)| entry.clone())
            .collect();
        let mut combined = self
            .management_retirements
            .get(&agent)
            .cloned()
            .unwrap_or_default();
        combined.extend(pairs.iter().map(|pair| [pair[0].clone(), pair[1].clone()]));
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        attached.coordinator.transition_management_retirement_set(
            &retirement_pair_refs(&combined),
            Some(&remaining),
        )?;
        self.management_retirements.insert(agent, combined);
        if remaining.is_empty() {
            self.management_pending.remove(&agent);
        } else {
            self.management_pending.insert(agent, remaining);
        }
        Ok(())
    }

    pub(crate) fn complete_management_retirement<F>(
        &mut self,
        agent: crate::service::AgentId,
        envelopes: [&crate::agent_sdk::RuntimeWork; 2],
        complete: F,
    ) -> Result<(), SharedAgentHostError>
    where
        F: FnOnce() -> Result<(), SharedAgentHostError>,
    {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        attached
            .coordinator
            .complete_management_retirement(envelopes, complete)?;
        drop(live);
        self.remove_management_retirement_pair(agent, envelopes)?;
        Ok(())
    }

    /// Only the lifecycle owner may release from a verified durable intent
    /// retirement marker, including after an ambiguous successful commit.
    pub(crate) fn release_completed_management_retirement(
        &mut self,
        agent: crate::service::AgentId,
        envelopes: [&crate::agent_sdk::RuntimeWork; 2],
    ) -> Result<(), SharedAgentHostError> {
        let keys = management_retirement_keys(agent, envelopes)?;
        if let Some(pending) = self.management_retirements.get(&agent)
            && !management_retirement_set_keys(agent, &retirement_pair_refs(pending))?
                .contains(&keys)
        {
            // This older durable terminal has no pair in the current family;
            // do not remove, replace or interfere with that family's gate.
            return Ok(());
        }
        let Some(attached) = self.generations.get(&agent) else {
            self.remove_management_retirement_pair(agent, envelopes)?;
            return Ok(());
        };
        attached
            .coordinator
            .release_completed_management_retirement(envelopes)?;
        self.remove_management_retirement_pair(agent, envelopes)?;
        Ok(())
    }

    fn remove_management_retirement_pair(
        &mut self,
        agent: crate::service::AgentId,
        envelopes: [&crate::agent_sdk::RuntimeWork; 2],
    ) -> Result<(), SharedAgentHostError> {
        let keys = management_retirement_keys(agent, envelopes)?;
        if let Some(pending) = self.management_retirements.get_mut(&agent) {
            let all = management_retirement_set_keys(agent, &retirement_pair_refs(pending))?;
            let index = all
                .iter()
                .position(|pair| *pair == keys)
                .ok_or(SharedAgentHostError::Conflict)?;
            pending.remove(index);
            if pending.is_empty() {
                self.management_retirements.remove(&agent);
            }
        }
        Ok(())
    }

    /// Shared certificate/attachment mechanics; callers retain their own
    /// exact admission predicates. The gate excludes pending management and
    /// retirement before any snapshot can replace their anchored history.
    #[cfg(test)]
    pub(crate) fn certified_checkpoint_for_test(
        &mut self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
    ) -> Result<(), SharedAgentHostError> {
        self.certified_checkpoint_for_admission(
            agent,
            work,
            authorization,
            expected_committee,
            signer,
        )
    }

    fn certified_checkpoint_for_admission(
        &mut self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
    ) -> Result<(), SharedAgentHostError> {
        self.certified_checkpoint_for_admission_inner(
            agent,
            work,
            authorization,
            expected_committee,
            signer,
        )
        .map(|_| ())
    }

    fn certified_checkpoint_for_admission_inner(
        &mut self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
    ) -> Result<bool, SharedAgentHostError> {
        if expected_committee.members().len() != 1
            || expected_committee.voter_count() != 1
            || expected_committee
                .member_by_node(signer.node())
                .is_none_or(|member| member.replica().role != ReplicaRole::Voter)
        {
            return Err(SharedAgentHostError::SnapshotCertificateInvalid);
        }
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        attached
            .coordinator
            .reserve_checkpoint_gate(work, authorization)?;
        let certificate = {
            let mut host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let candidate = match host.request_snapshot_compaction(agent) {
                Ok(candidate) => candidate,
                Err(error) => {
                    drop(host);
                    let _ = attached
                        .coordinator
                        .release_checkpoint_gate(work, authorization);
                    return Err(error);
                }
            };
            if candidate.claim().active_committee() != expected_committee {
                drop(host);
                let _ = attached
                    .coordinator
                    .release_checkpoint_gate(work, authorization);
                return Err(SharedAgentHostError::SnapshotCertificateInvalid);
            }
            let Some(signature) = signer.sign_snapshot_candidate(&candidate) else {
                drop(host);
                let _ = attached
                    .coordinator
                    .release_checkpoint_gate(work, authorization);
                return Err(SharedAgentHostError::SnapshotCertificateInvalid);
            };
            match SharedAgentSnapshotCertificate::new(candidate.claim().clone(), vec![signature]) {
                Ok(certificate) => certificate,
                Err(_) => {
                    drop(host);
                    let _ = attached
                        .coordinator
                        .release_checkpoint_gate(work, authorization);
                    return Err(SharedAgentHostError::SnapshotCertificateInvalid);
                }
            }
        };

        // Only a fully reconstructed and locally signed candidate can retire
        // the live worker. Signer refusal and candidate errors release the
        // checkpoint gate while preserving the exact existing attachment.
        self.retire(agent)?;
        let checkpoint = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .install_snapshot(agent, &certificate);

        // Restart always reconstructs this attachment from durable host
        // status. In-process failures make the same attempt here regardless
        // of whether retirement, signing, or installation failed.
        let reattachment = self.reattach_current(agent);
        match (checkpoint, reattachment) {
            (Ok(_), Ok(())) => Ok(true),
            (Err(error), Ok(())) => Err(error),
            (_, Err(error)) => Err(error),
        }
    }

    /// Explicit qualification path only. Automatic multi-voter pruning stays
    /// disabled until authenticated catch-up and retained-result availability
    /// have been qualified end to end.
    #[cfg(test)]
    pub(crate) fn certified_common_checkpoint_for_admission(
        &mut self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
    ) -> Result<SharedAgentCommonSnapshotCertificate, SharedAgentHostError> {
        self.certified_common_checkpoint_for_admission_inner(
            agent,
            work,
            authorization,
            expected_committee,
            signer,
            true,
        )
    }

    /// Qualification-only collection cut. The fixture retires every voter at
    /// this certified foundation before testing filesystem publication. Retiring
    /// only the source would let the other two commit a new election boundary.
    #[cfg(test)]
    pub(crate) fn collect_common_checkpoint_for_admission(
        &mut self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
    ) -> Result<SharedAgentCommonSnapshotCertificate, SharedAgentHostError> {
        self.certified_common_checkpoint_for_admission_inner(
            agent,
            work,
            authorization,
            expected_committee,
            signer,
            false,
        )
    }

    #[cfg(test)]
    fn certified_common_checkpoint_for_admission_inner(
        &mut self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
        install: bool,
    ) -> Result<SharedAgentCommonSnapshotCertificate, SharedAgentHostError> {
        let started = Instant::now();
        if expected_committee.members().len() != 3
            || expected_committee.voter_count() != 3
            || work.agent.0 != agent.0
            || !authorization.matches_work(work)
        {
            return Err(SharedAgentHostError::SnapshotCertificateInvalid);
        }
        self.ensure_reattached(agent)?;
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let worker = attached
            .coordinator
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::Unavailable)?;
        let barrier = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        if barrier.role != vos_raft::Role::Leader || barrier.commit_index != barrier.last_log_index
        {
            if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                eprintln!(
                    "common_checkpoint barrier_refusal node={:?} role={:?} term={} commit={} last={}",
                    self.network.agent_node_id(),
                    barrier.role,
                    barrier.current_term,
                    barrier.commit_index,
                    barrier.last_log_index
                );
            }
            return Err(SharedAgentHostError::Unavailable);
        }
        attached
            .coordinator
            .reserve_checkpoint_gate(work, authorization)?;
        let certificate = match attached
            .coordinator
            .collect_common_snapshot_certificate(expected_committee, signer)
        {
            Ok(certificate) => certificate,
            Err(error) => {
                let _ = attached
                    .coordinator
                    .release_checkpoint_gate(work, authorization);
                return Err(error);
            }
        };
        tracing::debug!(
            elapsed_us = started.elapsed().as_micros(),
            phase = "quorum",
            "Common checkpoint phase complete"
        );
        if !install {
            return Ok(certificate);
        }
        self.retire(agent)?;
        let installed = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .install_common_snapshot(agent, &certificate);
        tracing::debug!(
            elapsed_us = started.elapsed().as_micros(), result = ?installed,
            phase = "install", "Common checkpoint phase complete"
        );
        let reattached = self.reattach_current(agent);
        tracing::debug!(
            elapsed_us = started.elapsed().as_micros(), result = ?reattached,
            phase = "reattach", "Common checkpoint phase complete"
        );
        match (installed, reattached) {
            (Ok(_), Ok(())) => Ok(certificate),
            (Err(error), Ok(())) | (_, Err(error)) => Err(error),
        }
    }

    fn reattach_current(
        &mut self,
        agent: crate::service::AgentId,
    ) -> Result<(), SharedAgentHostError> {
        #[cfg(test)]
        if core::mem::take(&mut self.fail_reattach_once) {
            return Err(SharedAgentHostError::Unavailable);
        }
        if self.generations.contains_key(&agent) {
            return Ok(());
        }
        let status = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .show(agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        self.attach_status(status, false)
    }

    #[cfg(test)]
    pub(crate) fn fail_reattach_once_for_test(&mut self) {
        self.fail_reattach_once = true;
    }

    fn attach_status(
        &mut self,
        status: SharedAgentStatus,
        promotion_barrier: bool,
    ) -> Result<(), SharedAgentHostError> {
        let agent = status.generation.agent();
        let retirement = self.management_retirements.get(&agent).cloned();
        let pending_management = self.management_pending.get(&agent).cloned();
        if self.generations.contains_key(&agent) {
            return Err(SharedAgentHostError::Conflict);
        }
        let mut reservation = TransportAttachReservation::reserve(Arc::clone(&self.host), agent)?;
        let ordered_replies = Arc::new(OrderedReplyWaiters::default());
        // Recovery may reopen a database with durable commit_index ahead of
        // the journal application cursor. No new Raft event is guaranteed to
        // arrive, so drain that exact suffix before exposing a route or
        // deriving its current committee fingerprint.
        let attachment_status = {
            let mut host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            drain_committed(&mut host, agent, &ordered_replies)?;
            host.supervisor_attachment_status(agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?
        };
        // Recovery admission below needs only audited ledger capacity. Keep
        // each fresh audit under the same host lock, but do not ask `show` to
        // query actor lanes and snapshots whose results would be discarded.
        if let Some(pending) = &pending_management {
            let host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let required = host
                .management_recovery_admission_requirement(
                    agent,
                    &pending_management_refs(pending),
                    &retirement
                        .as_deref()
                        .unwrap_or(&[])
                        .iter()
                        .flatten()
                        .collect::<Vec<_>>(),
                )?
                .ok_or(SharedAgentHostError::CapacityExhausted)?;
            let (_, remaining, _) = host.capacity(agent)?;
            // Preserve every anchor; never checkpoint to make this set fit.
            if remaining < required as u64 + 1 {
                return Err(SharedAgentHostError::CapacityExhausted);
            }
        }
        if pending_management.is_none()
            && let Some(envelopes) = &retirement
        {
            let host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let required = host
                .management_retirement_set_admission_requirement(
                    agent,
                    &envelopes.iter().flatten().collect::<Vec<_>>(),
                )?
                .ok_or(SharedAgentHostError::CapacityExhausted)?;
            let (_, remaining, _) = host.capacity(agent)?;
            // The new one-voter worker must append its current-term no-op.
            if remaining < required as u64 + 1 {
                return Err(SharedAgentHostError::CapacityExhausted);
            }
        }
        let fingerprint = AttachmentFingerprint::from_attachment_status(&attachment_status)?;
        let local = self.network.agent_node_id();
        if !fingerprint.validates_local(local) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        // An original owner may return while a different voter remains leader.
        // Only exact replicated management custody can replace the local
        // promotion requirement; legacy/unregistered recovery still needs it.
        let retained_follower = !promotion_barrier
            && self.system_agents.contains(&agent)
            && fingerprint.members.len() == 3
            && fingerprint.voters.len() == 3
            && fingerprint.next_committee.is_none()
            && fingerprint.joint_old.is_none()
            && (pending_management.is_some() || retirement.is_some())
            && {
                let mut host = self
                    .host
                    .lock()
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
                let manifest = host.recovery_manifest(agent)?;
                manifest
                    .management_slot(crate::service::NodeId(local.0))
                    .is_some_and(|slot| {
                        pending_management.as_ref().is_none_or(|pending| {
                            pending.iter().all(|(anchor, envelope)| {
                                slot.members().iter().any(|member| {
                                    member.anchor() == anchor && member.envelope() == envelope
                                })
                            })
                        }) && retirement.as_ref().is_none_or(|retiring| {
                            retiring.iter().all(|pair| {
                                slot.members()
                                    .iter()
                                    .any(|member| member.envelope() == &pair[0])
                            })
                        })
                    })
            };
        let promotion_barrier = fingerprint.requires_promotion_barrier(
            promotion_barrier,
            self.system_agents.contains(&agent),
            pending_management.is_some() && !retained_follower,
            retirement.is_some() && !retained_follower,
        );
        #[cfg(test)]
        if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
            eprintln!(
                "management_attach node={local:?} retained_follower={retained_follower} promotion={promotion_barrier} system={} members={} voters={} pending={} retiring={}",
                self.system_agents.contains(&agent),
                fingerprint.members.len(),
                fingerprint.voters.len(),
                pending_management.as_ref().map_or(0, Vec::len),
                retirement.as_ref().map_or(0, Vec::len)
            );
        }
        let authenticated_snapshot = match status.snapshots {
            crate::agent::shared_host::SharedAgentSnapshotState::None => (0, 0),
            crate::agent::shared_host::SharedAgentSnapshotState::Installed {
                raft_index,
                raft_term,
                ..
            } => (raft_index, raft_term),
        };
        let route = fingerprint.protocol_route;
        #[cfg(test)]
        let raft_isolated = Arc::new(AtomicBool::new(false));
        let (mut worker, handle, receiver) = if fingerprint.owns_raft_worker(local) {
            let database = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .raft_database(agent)?;
            let storage = AgentNodeStorage::open(database, authenticated_snapshot)
                .map_err(|_| SharedAgentHostError::CorruptResidue)?;
            #[cfg(test)]
            let storage = {
                let mut storage = storage;
                storage.timing_node = local;
                storage
            };
            let transport = AgentRaftTransport::new(Arc::clone(&self.network), route);
            #[cfg(test)]
            let transport = transport.with_isolation(Arc::clone(&raft_isolated));
            let transport = Arc::new(transport);
            let mut config = vos_raft::Config::new(
                local,
                fingerprint.voters.clone(),
                attachment_status.replication_id,
            );
            config.max_append_entries = MAX_SHARED_RAFT_APPEND_ENTRIES;
            config.max_inflight_replications = 8;
            // Generic snapshots cannot represent an authenticated Agent
            // journal. Keep automatic compaction disabled until that bridge
            // carries the snapshot certificate/evidence protocol.
            config.compact_hysteresis = u64::MAX;
            let (sender, receiver) = std_mpsc::channel();
            let worker = vos_raft::Worker::try_spawn(storage, transport, config, Some(sender))
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            worker
                .wait_init()
                .map_err(|_| SharedAgentHostError::CorruptResidue)?;
            let handle = worker.handler();
            (Some(worker), Some(handle), Some(receiver))
        } else {
            // Observers authenticate and serve Merge/route data but do not
            // participate in Raft quorum or process Raft RPCs.
            (None, None, None)
        };
        if retained_follower && !promotion_barrier {
            let worker = handle
                .as_ref()
                .ok_or(SharedAgentHostError::TransportNotAttached)?;
            let before = futures_executor::block_on(worker.snapshot())
                .ok_or(SharedAgentHostError::Unavailable)?;
            #[cfg(test)]
            if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                eprintln!("management_attach_follower before={before:?}");
            }
            let attachment_barrier = RetainedAttachmentBarrier::from(&before);
            attachment_barrier.validate_scope(&fingerprint.voters, authenticated_snapshot.0)?;
            let mut host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            drain_committed(&mut host, agent, &ordered_replies)?;
            let applied = host.capacity(agent)?.0;
            let current = futures_executor::block_on(worker.snapshot())
                .ok_or(SharedAgentHostError::Unavailable)?;
            #[cfg(test)]
            if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                eprintln!("management_attach_follower applied={applied} after={current:?}");
            }
            attachment_barrier
                .validate_applied(&RetainedAttachmentBarrier::from(&current), applied)?;
        }
        if promotion_barrier {
            let recovery_worker = handle
                .as_ref()
                .ok_or(SharedAgentHostError::TransportNotAttached)?;
            // Serialize behind leader promotion: role publication can precede
            // its mandatory current-term no-op commit advance by one worker
            // step. The snapshot barrier proves the no-op and every recovered
            // tail row are committed before we derive admission capacity.
            let committed = system_promotion_barrier(
                || recovery_worker.role(),
                || {
                    futures_executor::block_on(recovery_worker.snapshot())
                        .map(|state| (state.role, state.commit_index, state.last_log_index))
                },
                ORDERED_REPLY_WAIT,
            )?;
            let mut host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            drain_committed(&mut host, agent, &ordered_replies)?;
            if host.capacity(agent)?.0 != committed {
                return Err(SharedAgentHostError::CorruptResidue);
            }
        }
        let lifecycle = Arc::new(RwLock::new(true));
        let apply_worker = handle.clone();
        let initial_admission = if let Some(pending) = &pending_management {
            let host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let required = host
                .management_recovery_admission_requirement(
                    agent,
                    &pending_management_refs(pending),
                    &retirement
                        .as_deref()
                        .unwrap_or(&[])
                        .iter()
                        .flatten()
                        .collect::<Vec<_>>(),
                )?
                .ok_or(SharedAgentHostError::CapacityExhausted)?;
            let (_, remaining, _) = host.capacity(agent)?;
            if remaining < required as u64 {
                return Err(SharedAgentHostError::CapacityExhausted);
            }
            ProposalAdmission {
                management_pending: Some(pending_management_keys(agent, pending)?),
                management_retirement: retirement
                    .as_ref()
                    .map(|pairs| {
                        management_retirement_set_keys(agent, &retirement_pair_refs(pairs))
                    })
                    .transpose()?,
                ..ProposalAdmission::default()
            }
        } else if let Some(envelopes) = &retirement {
            let host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let required = host
                .management_retirement_set_admission_requirement(
                    agent,
                    &envelopes.iter().flatten().collect::<Vec<_>>(),
                )?
                .ok_or(SharedAgentHostError::CapacityExhausted)?;
            let (_, remaining, _) = host.capacity(agent)?;
            if remaining < required as u64 {
                return Err(SharedAgentHostError::CapacityExhausted);
            }
            ProposalAdmission {
                management_retirement: Some(management_retirement_set_keys(
                    agent,
                    &retirement_pair_refs(envelopes),
                )?),
                ..ProposalAdmission::default()
            }
        } else {
            ProposalAdmission::default()
        };
        let management_recovery_scope = {
            let mut host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            if fingerprint.members.len() == 3
                && fingerprint.voters.len() == 3
                && host.is_system_bootstrap_agent(agent)?
            {
                let scope = host.management_recovery_scope(agent)?;
                if scope.0 != fingerprint.durable_route {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                Some(scope)
            } else {
                None
            }
        };
        let handler_impl = Arc::new(SharedRouteHandler {
            host: Arc::clone(&self.host),
            network: Arc::clone(&self.network),
            route,
            agent,
            route_nodes: fingerprint.members.iter().map(|(node, _)| *node).collect(),
            management_retention: management_recovery_scope.is_some(),
            worker: handle,
            proposal: Mutex::new(initial_admission),
            ordered_replies: Arc::clone(&ordered_replies),
            lifecycle: Arc::clone(&lifecycle),
            #[cfg(test)]
            raft_isolated,
            #[cfg(test)]
            management_custody_budget_checks: std::sync::atomic::AtomicUsize::new(0),
        });
        let handler: Arc<dyn AgentRouteHandler> = handler_impl.clone();
        let stale = Arc::new(AtomicBool::new(false));
        let merge_stop = Arc::new(AtomicBool::new(false));
        let apply_thread = if let Some(receiver) = receiver {
            let thread_worker = apply_worker;
            let host = Arc::clone(&self.host);
            let network = Arc::clone(&self.network);
            let route_handler = Arc::clone(&handler);
            let attached_fingerprint = fingerprint.clone();
            let thread_stale = Arc::clone(&stale);
            let thread_merge_stop = Arc::clone(&merge_stop);
            let thread_lifecycle = Arc::clone(&lifecycle);
            match std::thread::Builder::new()
                .name(format!("shared-agent-apply-{:02x?}", &agent.0[..4]))
                .spawn(move || {
                    while receiver.recv().is_ok() {
                        let Ok(mut host) = host.lock() else {
                            ordered_replies.fail_all();
                            thread_stale.store(true, Ordering::Release);
                            thread_merge_stop.store(true, Ordering::Release);
                            if let Some(worker) = &thread_worker {
                                let _ = worker.sender().send(vos_raft::RaftMsg::Shutdown);
                            }
                            retire_route_with_lease(
                                &network,
                                route,
                                &route_handler,
                                &thread_lifecycle,
                            );
                            return;
                        };
                        if let Err(error) = drain_committed(&mut host, agent, &ordered_replies) {
                            tracing::warn!(
                                ?agent,
                                ?error,
                                "retiring Shared route after committed replay failure"
                            );
                            ordered_replies.fail_all();
                            thread_stale.store(true, Ordering::Release);
                            thread_merge_stop.store(true, Ordering::Release);
                            if let Some(worker) = &thread_worker {
                                let _ = worker.sender().send(vos_raft::RaftMsg::Shutdown);
                            }
                            drop(host);
                            retire_route_with_lease(
                                &network,
                                route,
                                &route_handler,
                                &thread_lifecycle,
                            );
                            return;
                        }
                        let current = host
                            .supervisor_attachment_status(agent)
                            .ok()
                            .flatten()
                            .and_then(|status| {
                                AttachmentFingerprint::from_attachment_status(&status).ok()
                            });
                        if current.as_ref() != Some(&attached_fingerprint) {
                            ordered_replies.fail_all();
                            thread_stale.store(true, Ordering::Release);
                            thread_merge_stop.store(true, Ordering::Release);
                            if let Some(worker) = &thread_worker {
                                let _ = worker.sender().send(vos_raft::RaftMsg::Shutdown);
                            }
                            drop(host);
                            retire_route_with_lease(
                                &network,
                                route,
                                &route_handler,
                                &thread_lifecycle,
                            );
                            return;
                        }
                    }
                    // A closed notifier without an owning retirement means
                    // the worker stopped unexpectedly. Revoke the route and
                    // synchronous waiters immediately; `refresh` may then
                    // reopen the exact durable generation with a fresh
                    // worker. Pointer-qualified retirement cannot remove a
                    // newer handler owner.
                    ordered_replies.fail_all();
                    thread_stale.store(true, Ordering::Release);
                    thread_merge_stop.store(true, Ordering::Release);
                    retire_route_with_lease(&network, route, &route_handler, &thread_lifecycle);
                }) {
                Ok(thread) => Some(thread),
                Err(_) => {
                    merge_stop.store(true, Ordering::Release);
                    retire_route_with_lease(&self.network, route, &handler, &lifecycle);
                    if let Some(worker) = worker.take() {
                        worker.shutdown();
                    }
                    return Err(SharedAgentHostError::Unavailable);
                }
            }
        } else {
            None
        };
        let merge_thread = {
            let merge_handler = Arc::clone(&handler_impl);
            let thread_stop = Arc::clone(&merge_stop);
            match std::thread::Builder::new()
                .name(format!("shared-agent-merge-{:02x?}", &agent.0[..4]))
                .spawn(move || {
                    let mut cursor = 0;
                    while !thread_stop.load(Ordering::Acquire) {
                        merge_handler.pump_merge_once(local, &thread_stop, &mut cursor);
                        if thread_stop.load(Ordering::Acquire) {
                            break;
                        }
                        std::thread::sleep(MERGE_PUMP_INTERVAL);
                    }
                }) {
                Ok(thread) => Some(thread),
                Err(_) => {
                    merge_stop.store(true, Ordering::Release);
                    retire_route_with_lease(&self.network, route, &handler, &lifecycle);
                    if let Some(worker) = worker.take() {
                        worker.shutdown();
                    }
                    if let Some(thread) = apply_thread {
                        let _ = thread.join();
                    }
                    return Err(SharedAgentHostError::Unavailable);
                }
            }
        };
        // Expose the route only after both live backends exist. A fast inbound
        // request must never observe a handler whose apply notifier or Merge
        // pump failed to start.
        let Some(activation) = acquire_route_activation(&lifecycle, &stale) else {
            merge_stop.store(true, Ordering::Release);
            retire_route_with_lease(&self.network, route, &handler, &lifecycle);
            if let Some(worker) = worker.take() {
                worker.shutdown();
            }
            if let Some(thread) = apply_thread {
                let _ = thread.join();
            }
            if let Some(thread) = merge_thread {
                let _ = thread.join();
            }
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        if self
            .network
            .install_agent_route(route, fingerprint.members.clone(), Arc::clone(&handler))
            .is_err()
        {
            drop(activation);
            merge_stop.store(true, Ordering::Release);
            retire_route_with_lease(&self.network, route, &handler, &lifecycle);
            if let Some(worker) = worker.take() {
                worker.shutdown();
            }
            if let Some(thread) = apply_thread {
                let _ = thread.join();
            }
            if let Some(thread) = merge_thread {
                let _ = thread.join();
            }
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if let Err(error) = reservation.mark_attached() {
            drop(activation);
            merge_stop.store(true, Ordering::Release);
            retire_route_with_lease(&self.network, route, &handler, &lifecycle);
            if let Some(worker) = worker.take() {
                worker.shutdown();
            }
            if let Some(thread) = apply_thread {
                let _ = thread.join();
            }
            if let Some(thread) = merge_thread {
                let _ = thread.join();
            }
            return Err(error);
        }
        self.generations.insert(
            agent,
            AttachedGeneration {
                fingerprint,
                handler,
                coordinator: handler_impl,
                worker,
                apply_thread,
                merge_stop,
                merge_thread,
                stale,
                lifecycle: Arc::clone(&lifecycle),
            },
        );
        drop(activation);
        Ok(())
    }

    /// Reconcile newly provisioned generations and exact committee/peer
    /// changes. Removal retires the route owner and its unshared bindings.
    pub fn refresh(&mut self) -> Result<(), SharedAgentHostError> {
        let statuses = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .attachment_statuses()?;
        let live = statuses
            .iter()
            .filter(|status| status.local_role.is_some())
            .map(|status| status.generation.agent())
            .collect::<BTreeSet<_>>();
        let retired = self
            .generations
            .keys()
            .copied()
            .filter(|agent| !live.contains(agent))
            .collect::<Vec<_>>();
        for agent in retired {
            self.retire(agent)?;
        }
        for status in statuses {
            if status.local_role.is_none() {
                continue;
            }
            let agent = status.generation.agent();
            let fingerprint = AttachmentFingerprint::from_attachment_status(&status)?;
            let rebuild = self.generations.get(&agent).is_some_and(|attached| {
                attached.stale.load(Ordering::Acquire) || attached.fingerprint != fingerprint
            });
            if rebuild {
                self.retire(agent)?;
            }
            if !self.generations.contains_key(&agent) {
                // Initial/rebuilt attachment still needs the complete status
                // (including its authenticated snapshot). Refreshing an
                // unchanged fingerprint must not query unrelated actor lanes.
                let status = self
                    .host
                    .lock()
                    .map_err(|_| SharedAgentHostError::Unavailable)?
                    .show(agent)?
                    .ok_or(SharedAgentHostError::AgentNotFound)?;
                self.attach_status(status, false)?;
            }
        }
        Ok(())
    }

    /// Reconcile transport ownership, then project every live generation from
    /// its authenticated SDK descriptor and actor directory. The per-route
    /// lifecycle lease prevents a concurrent worker failure from leaving a
    /// projection visible after its exact network attachment was revoked.
    pub(crate) fn supervisor_projections(
        &mut self,
    ) -> Result<Vec<SharedAgentRuntimeProjection>, SharedAgentHostError> {
        self.supervisor_projections_scoped(None)
    }

    pub(crate) fn supervisor_projection_for(
        &mut self,
        agent: crate::service::AgentId,
    ) -> Result<Vec<SharedAgentRuntimeProjection>, SharedAgentHostError> {
        self.supervisor_projections_scoped(Some(agent))
    }

    pub(crate) fn supervisor_route_handle(
        &self,
        agent: crate::service::AgentId,
    ) -> Result<SharedAgentRouteHandle, SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        Ok(SharedAgentRouteHandle {
            coordinator: Arc::downgrade(&attached.coordinator),
            fingerprint: attached.fingerprint.clone(),
            stale: Arc::clone(&attached.stale),
        })
    }

    pub(crate) fn supervisor_generation_handles(
        &mut self,
    ) -> Result<Vec<SharedAgentRouteHandle>, SharedAgentHostError> {
        self.refresh()?;
        self.generations
            .keys()
            .map(|agent| self.supervisor_route_handle(*agent))
            .collect()
    }

    fn supervisor_projections_scoped(
        &mut self,
        only: Option<crate::service::AgentId>,
    ) -> Result<Vec<SharedAgentRuntimeProjection>, SharedAgentHostError> {
        self.refresh()?;
        let agents = match only {
            Some(agent) => vec![agent],
            None => self.generations.keys().copied().collect(),
        };
        let mut projections = Vec::with_capacity(agents.len());
        for agent in agents {
            let attached = self
                .generations
                .get(&agent)
                .ok_or(SharedAgentHostError::TransportNotAttached)?;
            // Route operations always take the generation lease before the
            // host mutex. Retirement may update the host first, but drops
            // that mutex guard before taking the exclusive generation lease,
            // so there is no host -> lifecycle lock inversion.
            let live = attached
                .lifecycle
                .read()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            if !*live || attached.stale.load(Ordering::Acquire) {
                return Err(SharedAgentHostError::TransportNotAttached);
            }
            let host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let status = host
                .supervisor_attachment_status(agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?;
            if status.transport != SharedAgentTransportState::Attached
                || AttachmentFingerprint::from_attachment_status(&status)? != attached.fingerprint
            {
                return Err(SharedAgentHostError::TransportNotAttached);
            }
            let projection = host.clean_runtime_projection(agent)?;
            if !projection_matches_attachment_status(&projection, &status) {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            if attached.stale.load(Ordering::Acquire) {
                return Err(SharedAgentHostError::TransportNotAttached);
            }
            projections.push(projection);
        }
        Ok(projections)
    }

    /// Reconcile transport ownership, hold every selected generation lease,
    /// and authenticate a complete authority subset against the same physical
    /// host/fingerprints used by invocation dispatch. A concurrent retirement
    /// marks the generation stale and makes the audit fail before publication.
    pub(crate) fn audit_authority_projection(
        &mut self,
        head: crate::agent_sdk::authority::AuthorityProjectionHead,
        projected: &[crate::agent::supervisor_adapters::AgentAuthorityRouteProjection],
        root: Option<&crate::agent::invocation_preparation::PhysicalRootLineage>,
    ) -> Result<crate::agent::shared_host::SharedAuthorityProjectionAudit, SharedAgentHostError>
    {
        self.audit_authority_projection_scoped(head, projected, root, false)
    }

    pub(crate) fn audit_system_authority_projection(
        &mut self,
        head: crate::agent_sdk::authority::AuthorityProjectionHead,
        projected: &[crate::agent::supervisor_adapters::AgentAuthorityRouteProjection],
        root: &crate::agent::invocation_preparation::PhysicalRootLineage,
    ) -> Result<crate::agent::shared_host::SharedAuthorityProjectionAudit, SharedAgentHostError>
    {
        self.audit_authority_projection_scoped(head, projected, Some(root), true)
    }

    fn audit_authority_projection_scoped(
        &mut self,
        head: crate::agent_sdk::authority::AuthorityProjectionHead,
        projected: &[crate::agent::supervisor_adapters::AgentAuthorityRouteProjection],
        root: Option<&crate::agent::invocation_preparation::PhysicalRootLineage>,
        system_only: bool,
    ) -> Result<crate::agent::shared_host::SharedAuthorityProjectionAudit, SharedAgentHostError>
    {
        self.refresh()?;
        let leased_agents = if system_only {
            vec![crate::service::AgentId(
                root.ok_or(SharedAgentHostError::ScopeMismatch)?.agent.0,
            )]
        } else {
            self.generations.keys().copied().collect::<Vec<_>>()
        };
        let mut leases = Vec::with_capacity(leased_agents.len());
        for agent in &leased_agents {
            let attached = self
                .generations
                .get(agent)
                .ok_or(SharedAgentHostError::TransportNotAttached)?;
            let lease = attached
                .lifecycle
                .read()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            if !*lease || attached.stale.load(Ordering::Acquire) {
                return Err(SharedAgentHostError::TransportNotAttached);
            }
            leases.push(lease);
        }
        let host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        for agent in &leased_agents {
            let attached = self
                .generations
                .get(agent)
                .ok_or(SharedAgentHostError::TransportNotAttached)?;
            let status = host
                .supervisor_attachment_status(*agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?;
            if status.transport != SharedAgentTransportState::Attached
                || AttachmentFingerprint::from_attachment_status(&status)? != attached.fingerprint
                || attached.stale.load(Ordering::Acquire)
            {
                return Err(SharedAgentHostError::TransportNotAttached);
            }
        }
        let audit = if system_only {
            host.audit_system_authority_projection(
                head,
                projected,
                root.ok_or(SharedAgentHostError::ScopeMismatch)?,
            )?
        } else {
            host.audit_authority_projection(head, projected, root)?
        };
        if leased_agents.iter().any(|agent| {
            self.generations
                .get(agent)
                .is_none_or(|attached| attached.stale.load(Ordering::Acquire))
        }) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        drop(host);
        drop(leases);
        Ok(audit)
    }

    /// Resolve physical invocation material while holding the same
    /// generation lifecycle lease used by clean route dispatch. The catalog
    /// read and status/fingerprint checks therefore cannot be detached from
    /// the route owner which the supervisor published.
    pub(crate) fn supervisor_invocation_material(
        &self,
        agent: vos_agent_sdk::AgentId,
        actor: vos_agent_sdk::ActorId,
    ) -> Result<
        crate::agent::invocation_preparation::PhysicalInvocationMaterial,
        SharedAgentHostError,
    > {
        let agent = crate::service::AgentId(agent.0);
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let status = host
            .supervisor_attachment_status(agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if status.transport != SharedAgentTransportState::Attached
            || AttachmentFingerprint::from_attachment_status(&status)? != attached.fingerprint
        {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let material = host.supervisor_invocation_material(agent, actor)?;
        let projection = SharedAgentRuntimeProjection {
            descriptor: material.descriptor.clone(),
            actors: vec![material.actor.clone()],
        };
        if !projection_matches_attachment_status(&projection, &status) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        Ok(material)
    }

    /// Invoke one exact clean SDK work item through this attachment's owning
    /// generation. Ordered calls use the authenticated Raft proposer; Merge
    /// and Local calls remain on their profile-defined physical lanes.
    pub(crate) fn supervisor_invoke(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        work: InvocationWork,
        authorization: InvocationAuthorization,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        self.supervisor_invocation_operation(
            expected,
            crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Invoke {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                work,
                authorization,
            },
            false,
            SupervisorAdmission::Ordinary,
        )
    }

    pub(crate) fn supervisor_invoke_terminal(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        work: InvocationWork,
        authorization: InvocationAuthorization,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        self.supervisor_invocation_operation(
            expected,
            crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Invoke {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                work,
                authorization,
            },
            true,
            SupervisorAdmission::Ordinary,
        )
    }

    /// Only the lifecycle owner may submit an already durable management
    /// envelope here. Remote ingress continues to use ordinary admission.
    pub(crate) fn supervisor_invoke_persisted_management(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        work: InvocationWork,
        authorization: InvocationAuthorization,
        anchor: &crate::agent::clean_management_intent::ManagementJournalAnchor,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        if !matches!(work.mode, crate::agent_sdk::MethodMode::Linear)
            || !matches!(&authorization, InvocationAuthorization::PublicPreflight(preflight) if preflight.matches_work(&work))
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.supervisor_invocation_operation(
            expected,
            crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Invoke {
                context: RuntimeExecutionContext::Direct,
                work,
                authorization,
            },
            true,
            SupervisorAdmission::PersistedManagement(anchor),
        )
    }

    pub(crate) fn supervisor_resume(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        work: InvocationWork,
        authorization: InvocationAuthorization,
        yielded: crate::agent_sdk::YieldedInvocation,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        self.supervisor_invocation_operation(
            expected,
            crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Resume {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                work,
                authorization,
                yielded,
            },
            false,
            SupervisorAdmission::Ordinary,
        )
    }

    pub(crate) fn supervisor_acknowledge(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        work: InvocationWork,
        authorization: InvocationAuthorization,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        self.supervisor_invocation_operation(
            expected,
            crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Acknowledge {
                work,
                authorization,
            },
            false,
            SupervisorAdmission::Ordinary,
        )
    }

    pub(crate) fn supervisor_acknowledge_management_retirement(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        work: InvocationWork,
        authorization: InvocationAuthorization,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        self.supervisor_invocation_operation(
            expected,
            crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Acknowledge {
                work,
                authorization,
            },
            false,
            SupervisorAdmission::ReservedManagementRetirement,
        )
    }

    pub(crate) fn supervisor_acknowledge_management_denial(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        proof: &crate::agent::clean_bootstrap::VerifiedManagementDenial,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        let (anchor, envelope) = proof.envelope();
        self.acknowledge_pending_management_result(expected, anchor, envelope)
    }

    pub(crate) fn supervisor_acknowledge_admin_result(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        proof: &crate::agent::clean_bootstrap::admin_dispatch::terminal::RetainedAdminResult,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        let (anchor, envelope) = proof.envelope();
        self.acknowledge_pending_management_result(expected, anchor, envelope)
    }

    pub(crate) fn supervisor_acknowledge_genesis_publication(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        proof: &crate::agent::clean_bootstrap::RetainedGenesisPublicationReply,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        let (anchor, envelope) = proof.envelope();
        self.acknowledge_pending_management_result(expected, anchor, envelope)
    }

    fn acknowledge_pending_management_result(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        anchor: &crate::agent::clean_management_intent::ManagementJournalAnchor,
        envelope: &crate::agent_sdk::RuntimeWork,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        let crate::agent_sdk::RuntimeWork::Invoke {
            invocation,
            authorization,
            ..
        } = envelope
        else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        self.ensure_management_pending_member(
            crate::service::AgentId(invocation.agent.0),
            anchor,
            envelope,
        )?;
        self.supervisor_invocation_operation(
            expected,
            crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Acknowledge {
                work: (**invocation).clone(),
                authorization: (**authorization).clone(),
            },
            false,
            SupervisorAdmission::ReservedManagementResult,
        )
    }

    fn supervisor_invocation_operation(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        request: crate::agent::shared_journal_driver::CleanInvocationReplayRequest,
        terminal_only: bool,
        admission: SupervisorAdmission<'_>,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        let agent = crate::service::AgentId(request.work().agent.0);
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        Self::execute_generation(
            SharedGenerationAccess {
                coordinator: &attached.coordinator,
                fingerprint: &attached.fingerprint,
                stale: &attached.stale,
            },
            expected,
            request,
            terminal_only,
            admission,
        )
    }

    fn execute_generation(
        attached: SharedGenerationAccess<'_>,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        request: crate::agent::shared_journal_driver::CleanInvocationReplayRequest,
        terminal_only: bool,
        admission: SupervisorAdmission<'_>,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        let work = request.work();
        if matches!(
            admission,
            SupervisorAdmission::ReservedManagementRetirement
                | SupervisorAdmission::ReservedManagementResult
        ) && (work.mode != MethodMode::Linear
            || !matches!(
                &request,
                crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Acknowledge { .. }
            ))
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let authorization = request.authorization();
        let agent = crate::service::AgentId(work.agent.0);
        if agent != attached.coordinator.agent {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        // Keep the same lifecycle -> host order as the network route handler.
        // `retire` releases its host guard before requesting the write lease.
        let live = attached
            .coordinator
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        {
            let host = attached
                .coordinator
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let status = host
                .supervisor_attachment_status(agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?;
            if status.transport != SharedAgentTransportState::Attached
                || AttachmentFingerprint::from_attachment_status(&status)? != *attached.fingerprint
            {
                return Err(SharedAgentHostError::TransportNotAttached);
            }
            let material = host.supervisor_invocation_material(agent, work.actor)?;
            if !crate::agent::supervisor_adapters::physical_material_authorizes_work(
                &material,
                expected,
                RuntimeExecutionContext::Direct,
                work,
                authorization,
            ) {
                return Err(SharedAgentHostError::InvalidProvision);
            }
            let projection = SharedAgentRuntimeProjection {
                descriptor: material.descriptor,
                actors: vec![material.actor],
            };
            if !projection_matches_attachment_status(&projection, &status)
                || !work_matches_projection(work, authorization, &projection)
                || projection.descriptor.identity.space != expected.key().space()
                || projection.descriptor.identity.agent != expected.key().agent()
                || projection.descriptor.identity.profile != expected.profile()
                || projection.descriptor.identity.runtime_deployment
                    != expected.runtime_deployment()
                || projection.actors.len() != 1
                || projection.actors[0].entry.actor != expected.key().actor()
                || projection.actors[0].incarnation != expected.incarnation()
                || projection.actors[0].entry.deployment != expected.actor_deployment()
                || projection.actors[0].entry.program != expected.actor_program()
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
        }
        if attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let scope = work.mode.invocation_scope();
        let _nonordered_admission =
            if matches!(scope, InvocationScope::Merge | InvocationScope::Local) {
                let proposal = attached
                    .coordinator
                    .proposal
                    .lock()
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
                if proposal.is_reserved() {
                    return Err(SharedAgentHostError::CapacityExhausted);
                }
                Some(proposal)
            } else {
                None
            };
        match scope {
            InvocationScope::Ordered
                if matches!(admission, SupervisorAdmission::ReservedManagementResult) =>
            {
                let key = ManagementInvocationKey::new(request.work(), request.authorization());
                attached
                    .coordinator
                    .submit_clean_ordered_operation_with_admission(
                        request,
                        false,
                        Some(ReservedSubmission::ManagementResult(key)),
                        InvocationClock::Current,
                    )
                    .map(|submission| submission.outcome)
            }
            InvocationScope::Ordered
                if matches!(admission, SupervisorAdmission::ReservedManagementRetirement) =>
            {
                let key = ManagementInvocationKey::new(request.work(), request.authorization());
                attached
                    .coordinator
                    .submit_clean_ordered_operation_with_admission(
                        request,
                        false,
                        Some(ReservedSubmission::ManagementRetirement(key)),
                        InvocationClock::Current,
                    )
                    .map(|submission| submission.outcome)
            }
            InvocationScope::Ordered
                if matches!(admission, SupervisorAdmission::PersistedManagement(_)) =>
            {
                let SupervisorAdmission::PersistedManagement(anchor) = admission else {
                    unreachable!()
                };
                attached
                    .coordinator
                    .submit_clean_ordered_operation_with_admission(
                        request,
                        true,
                        None,
                        InvocationClock::PersistedManagement(anchor),
                    )
                    .map(|submission| submission.outcome)
            }
            InvocationScope::Ordered if terminal_only => attached
                .coordinator
                .submit_terminal_clean_ordered_operation(request)
                .map(|submission| submission.outcome),
            InvocationScope::Ordered => attached
                .coordinator
                .submit_clean_ordered_operation(request)
                .map(|submission| submission.outcome),
            InvocationScope::Merge => attached
                .coordinator
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .apply_clean_merge_operation(agent, request),
            InvocationScope::Local => attached
                .coordinator
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .apply_clean_local_operation(agent, request),
        }
    }

    /// Internal root bootstrap only; ordinary routed calls retain their exact
    /// caller-supplied authorization and use the supervisor execution path.
    pub(crate) fn invoke_bootstrap(
        &self,
        agent: crate::service::AgentId,
        work: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
    ) -> Result<CleanOrderedSubmission, SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        attached
            .coordinator
            .submit_clean_ordered_operation_with_admission(
                crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Invoke {
                    context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                    work,
                    authorization,
                },
                false,
                None,
                InvocationClock::Bootstrap,
            )
    }

    /// Observe startup readiness without waiting for election. This does wait
    /// for the worker snapshot and committed-state drain, but grants no command
    /// publication permission on its own.
    /// Submission still rechecks leadership and all ordinary admission guards.
    pub(crate) fn bootstrap_is_local_leader(
        &self,
        agent: crate::service::AgentId,
    ) -> Result<bool, SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let worker = attached
            .coordinator
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        #[cfg(test)]
        tracing::debug!(snapshot = ?worker.cached_snapshot(), "pending system bootstrap election observation");
        if worker.role() != vos_raft::Role::Leader {
            return Ok(false);
        }
        let snapshot = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        if snapshot.role != vos_raft::Role::Leader
            || snapshot.commit_index != snapshot.last_log_index
        {
            return Ok(false);
        }
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, agent, &attached.coordinator.ordered_replies)?;
        if host.capacity(agent)?.0 != snapshot.commit_index {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        Ok(true)
    }

    #[cfg(test)]
    pub(crate) fn bootstrap_raft_role_for_test(
        &self,
        agent: crate::service::AgentId,
    ) -> Result<vos_raft::Role, SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let worker = attached
            .coordinator
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        futures_executor::block_on(worker.snapshot())
            .map(|snapshot| snapshot.role)
            .ok_or(SharedAgentHostError::Unavailable)
    }

    /// Submit an exact clean management request, including any deterministic
    /// artifact chunk prefix, through the live Raft worker.
    pub(crate) fn manage_clean(
        &self,
        agent: crate::service::AgentId,
        request: crate::agent_sdk::ManagementRequest,
        authority: crate::agent_sdk::authority::AuthorityReceipt,
        artifacts: crate::agent::driver::SdkManagementArtifacts<'_>,
    ) -> Result<CleanManagementSubmission, SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        attached
            .coordinator
            .submit_clean_management(request, authority, artifacts)
    }

    /// Only the retained original owner can submit this exact ordinary Shared
    /// Install on another leader. Peer progress is never application evidence.
    #[cfg(target_os = "linux")]
    pub(crate) fn manage_clean_from_retained_owner(
        &self,
        agent: crate::service::AgentId,
        request: crate::agent_sdk::ManagementRequest,
        authority: crate::agent_sdk::authority::AuthorityReceipt,
        artifacts: crate::agent::driver::SdkManagementArtifacts<'_>,
        owner: super::agent_protocol::ForwardedSharedInstallOwner,
    ) -> Result<CleanManagementSubmission, SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let coordinator = &attached.coordinator;
        let worker = coordinator
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if coordinator.has_local_proposer(worker) {
            coordinator.submit_clean_management_with_owner(
                request,
                authority,
                artifacts,
                Some((self.network.agent_node_id(), owner)),
            )
        } else {
            let crate::agent::driver::SdkManagementArtifacts::Actor(package) = artifacts else {
                return Err(SharedAgentHostError::ScopeMismatch);
            };
            tracing::debug!(
                phase = "origin_forwarded",
                node = ?self.network.agent_node_id(),
                ?agent,
                route = ?coordinator.route,
                request = ?request.commitment(),
                authority = ?authority.commitment(),
                "Shared Install forwarding provenance"
            );
            coordinator.forward_shared_install(owner, request, authority, package)
        }
    }

    #[cfg(test)]
    pub(crate) fn attachment_for_test(
        &self,
        agent: crate::service::AgentId,
    ) -> Option<(Arc<dyn AgentRouteHandler>, bool)> {
        self.generations
            .get(&agent)
            .map(|attached| (Arc::clone(&attached.handler), attached.worker.is_some()))
    }

    /// Capture the real handler's absent-capsule decision, then retry that
    /// exact submission after its first Invoke has independently committed.
    /// The physical fixture controls that interleaving without sleeps or a
    /// fabricated manifest, exercising the proposal-boundary recheck itself.
    #[cfg(test)]
    pub(crate) fn stage_management_custody_retry_for_test(
        &self,
        agent: crate::service::AgentId,
        owner: NodeId,
        member: &SharedManagementRecoveryMember,
    ) -> Box<dyn FnOnce()> {
        let coordinator = Arc::clone(&self.generations.get(&agent).unwrap().coordinator);
        let member = member.clone();
        let registration = {
            let mut host = coordinator.host.lock().unwrap();
            drain_committed(&mut host, agent, &coordinator.ordered_replies).unwrap();
            let manifest = host.recovery_manifest(agent).unwrap();
            let slot = manifest
                .management_slot(crate::service::NodeId(owner.0))
                .unwrap();
            let index = slot
                .members()
                .iter()
                .position(|saved| saved == &member)
                .unwrap();
            assert!(slot.members_evidence()[index].invoke().is_none());
            slot.registration().commitment()
        };
        Box::new(move || {
            let request =
                crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Invoke {
                    context: RuntimeExecutionContext::Direct,
                    work: member.work().clone(),
                    authorization: member.authorization().clone(),
                };
            let (before, expected_input, expected_outcome) = {
                let mut host = coordinator.host.lock().unwrap();
                drain_committed(&mut host, agent, &coordinator.ordered_replies).unwrap();
                let manifest = host.recovery_manifest(agent).unwrap();
                let slot = manifest
                    .management_slot(crate::service::NodeId(owner.0))
                    .unwrap();
                assert_eq!(slot.registration().commitment(), registration);
                let index = slot
                    .members()
                    .iter()
                    .position(|saved| saved == &member)
                    .unwrap();
                let first = slot.members_evidence()[index].invoke().unwrap();
                let (audited_capacity, capacity_manifest) =
                    host.capacity_and_recovery_manifest(agent).unwrap();
                assert_eq!(capacity_manifest, manifest);
                let mut substituted = request.clone();
                let crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Invoke {
                    work,
                    ..
                } = &mut substituted
                else {
                    unreachable!()
                };
                work.gas -= 1;
                assert!(matches!(
                    coordinator.validate_management_custody(
                        &mut host,
                        owner,
                        Hash(registration.0),
                        Hash(member.commitment().0),
                        &substituted,
                        InvocationClock::PersistedManagement(member.anchor()),
                        audited_capacity.1,
                        Some(capacity_manifest.clone()),
                    ),
                    Err(SharedAgentHostError::ScopeMismatch)
                ));
                let mut substituted = request.clone();
                let crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Invoke {
                    authorization: InvocationAuthorization::PublicPreflight(preflight),
                    ..
                } = &mut substituted
                else {
                    unreachable!()
                };
                preflight.observed_slot += 1;
                assert!(matches!(
                    coordinator.validate_management_custody(
                        &mut host,
                        owner,
                        Hash(registration.0),
                        Hash(member.commitment().0),
                        &substituted,
                        InvocationClock::PersistedManagement(member.anchor()),
                        audited_capacity.1,
                        Some(capacity_manifest.clone()),
                    ),
                    Err(SharedAgentHostError::ScopeMismatch)
                ));
                let mut late_anchor = member.anchor().clone();
                late_anchor.ordered.index += 1;
                assert!(matches!(
                    coordinator.validate_management_custody(
                        &mut host,
                        owner,
                        Hash(registration.0),
                        Hash(member.commitment().0),
                        &request,
                        InvocationClock::PersistedManagement(&late_anchor),
                        audited_capacity.1,
                        Some(capacity_manifest),
                    ),
                    Err(SharedAgentHostError::ScopeMismatch)
                ));
                (
                    (host.journal_position(agent).unwrap(), manifest.encode()),
                    first.input_id(),
                    first.outcome().clone(),
                )
            };
            let budget_checks = coordinator
                .management_custody_budget_checks
                .load(Ordering::Relaxed);
            let retry = coordinator
                .submit_clean_ordered_operation_with_admission(
                    request,
                    true,
                    Some(ReservedSubmission::ManagementCustody {
                        owner,
                        registration: Hash(registration.0),
                        member: Hash(member.commitment().0),
                    }),
                    InvocationClock::PersistedManagement(member.anchor()),
                )
                .unwrap();
            assert_eq!(retry.input, Some(expected_input));
            assert_eq!(retry.outcome, expected_outcome);
            assert!(!retry.new_slot);
            assert_eq!(
                coordinator
                    .management_custody_budget_checks
                    .load(Ordering::Relaxed),
                budget_checks,
                "a first capsule appearing behind proposal exclusion must not reenter new-row budgets"
            );
            let mut host = coordinator.host.lock().unwrap();
            drain_committed(&mut host, agent, &coordinator.ordered_replies).unwrap();
            assert_eq!(
                (
                    host.journal_position(agent).unwrap(),
                    host.recovery_manifest(agent).unwrap().encode()
                ),
                before,
                "stale absence must reuse the exact first capsule without changing authenticated history"
            );
        })
    }

    #[cfg(test)]
    pub(crate) fn assert_merge_noop_gate_for_test(&self, agent: crate::service::AgentId) {
        let coordinator = &self.generations.get(&agent).unwrap().coordinator;
        let sender = self.network.agent_node_id();
        let proposal = coordinator.proposal.lock().unwrap();
        let host = self.host.lock().unwrap();
        let (send, receive) = std_mpsc::channel();
        let worker = Arc::clone(coordinator);
        let thread = std::thread::spawn(move || {
            let _ = send.send(worker.sync_merge_heads(sender, Vec::new()).is_ok());
        });
        let empty = receive.recv_timeout(Duration::from_secs(1));
        drop(host);
        drop(proposal);
        thread.join().unwrap();
        assert_eq!(empty, Ok(true), "empty Merge must not wait for either lock");

        let registration = crate::agent::shared_recovery::management_recovery_fixture_for_test(1, 9);
        let mut proposal = coordinator.proposal.lock().unwrap();
        assert!(!proposal.is_reserved());
        proposal.checkpoint_gate = Some(ManagementInvocationKey::new(
            registration.work(),
            registration.authorization(),
        ));
        drop(proposal);
        let host = self.host.lock().unwrap();
        let (send, receive) = std_mpsc::channel();
        let worker = Arc::clone(coordinator);
        let thread = std::thread::spawn(move || {
            let _ = send.send(
                worker
                    .sync_merge_heads(sender, vec![Hash([1; 32])])
                    .is_err(),
            );
        });
        let nonempty = receive.recv_timeout(Duration::from_secs(1));
        drop(host);
        thread.join().unwrap();
        coordinator.proposal.lock().unwrap().checkpoint_gate = None;
        assert_eq!(
            nonempty,
            Ok(true),
            "nonempty Merge must honor the reservation"
        );
    }

    #[cfg(test)]
    pub(crate) fn mark_stale_for_test(&self, agent: crate::service::AgentId) -> bool {
        self.generations.get(&agent).is_some_and(|attached| {
            attached.stale.store(true, Ordering::Release);
            true
        })
    }

    #[cfg(test)]
    pub(crate) fn retire_attachment_for_test(
        &mut self,
        agent: crate::service::AgentId,
    ) -> Result<(), SharedAgentHostError> {
        self.retire(agent)
    }

    fn retire(&mut self, agent: crate::service::AgentId) -> Result<(), SharedAgentHostError> {
        let Some(mut attached) = self.generations.remove(&agent) else {
            return Ok(());
        };
        // Stop admitting work before waiting on the host mutex. The existing
        // Attached lease already blocks snapshot/GC, and removing the route
        // bounds the set of callers which can still contend for this host.
        self.network
            .retire_agent_route(attached.fingerprint.protocol_route, &attached.handler);
        // Reserve the destructive storage boundary throughout ordered route
        // revocation and worker/thread shutdown. Snapshot replacement and GC
        // remain blocked until every cached database user is gone.
        let stop_result = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)
            .and_then(|mut host| host.mark_transport_stopping(agent));
        attached.merge_stop.store(true, Ordering::Release);
        let mut live = attached
            .lifecycle
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *live = false;
        drop(live);
        if let Some(worker) = attached.worker.take() {
            worker.shutdown();
        }
        if let Some(thread) = attached.apply_thread.take() {
            let _ = thread.join();
        }
        if let Some(thread) = attached.merge_thread.take() {
            let _ = thread.join();
        }
        stop_result?;
        self.host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .release_transport_attachment(agent)
    }
}

impl Drop for SharedAgentNetworkHost {
    fn drop(&mut self) {
        let agents = self.generations.keys().copied().collect::<Vec<_>>();
        for agent in agents {
            let _ = self.retire(agent);
        }
    }
}

fn projection_matches_attachment_status(
    projection: &SharedAgentRuntimeProjection,
    status: &crate::agent::shared_host::SharedAgentAttachmentStatus,
) -> bool {
    let identity = &projection.descriptor.identity;
    projection.descriptor.validate().is_ok()
        && identity.profile == vos_agent_sdk::AgentProfile::Shared
        && status.identity.profile == crate::agent::AgentProfile::Shared
        && identity.space.0 == status.identity.space.0
        && identity.agent.0 == status.identity.agent.0
        && identity.owner.0 == status.identity.owner.0
        && identity.runtime_deployment.0 == status.identity.runtime_deployment.0
        && identity.runtime_program.0 == status.identity.runtime_program.0
        && identity.runtime_producer.0 == status.identity.runtime_producer.0
        && identity.transition_producer.0 == status.identity.transition_producer.0
        && status.generation.space().0 == identity.space.0
        && status.generation.agent().0 == identity.agent.0
}

fn work_matches_projection(
    work: &InvocationWork,
    authorization: &InvocationAuthorization,
    projection: &SharedAgentRuntimeProjection,
) -> bool {
    let identity = &projection.descriptor.identity;
    if !work.validate()
        || !authorization.matches_work(work)
        || identity.profile != vos_agent_sdk::AgentProfile::Shared
        || work.space != identity.space
        || work.agent != identity.agent
        || work.runtime_deployment != identity.runtime_deployment
    {
        return false;
    }
    projection
        .actors
        .binary_search_by_key(&work.actor, |record| record.entry.actor)
        .ok()
        .and_then(|position| projection.actors.get(position))
        .is_some_and(|record| {
            record.validate().is_ok()
                && !record.entry.suspended
                && record.incarnation == work.incarnation
                && record.entry.deployment == work.deployment
                && record.entry.program == work.program
        })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;
    use crate::raft::RAFT_LOG;

    #[test]
    fn committed_proposal_progress_is_retryable_but_stable_mismatch_is_corrupt() {
        let fixture = crate::agent::shared_recovery::management_recovery_fixture_for_test(1, 9);
        let key = ManagementInvocationKey::new(fixture.work(), fixture.authorization());
        let proposal = ProposalAdmission {
            checkpoint_gate: Some(key),
            ..ProposalAdmission::default()
        };
        let before = CommittedProposalBarrier {
            role: vos_raft::Role::Follower,
            term: 2,
            committed: 30,
            last: 30,
        };
        for current in [
            CommittedProposalBarrier {
                committed: 33,
                last: 33,
                ..before
            },
            CommittedProposalBarrier { last: 31, ..before },
            CommittedProposalBarrier { term: 3, ..before },
            CommittedProposalBarrier {
                role: vos_raft::Role::Leader,
                ..before
            },
        ] {
            // Applied rows may already reflect the newer commit, or the
            // worker may have advanced after the drain returned Idle.
            for applied in [before.committed, current.committed] {
                assert_eq!(
                    before.validate_applied(current, applied),
                    Err(SharedAgentHostError::Unavailable)
                );
                assert_eq!(proposal.checkpoint_gate, Some(key));
            }
        }
        for applied in [before.committed - 1, before.committed + 1] {
            assert_eq!(
                before.validate_applied(before, applied),
                Err(SharedAgentHostError::CorruptResidue)
            );
            assert_eq!(proposal.checkpoint_gate, Some(key));
        }
        assert_eq!(before.validate_applied(before, before.committed), Ok(()));
        assert_eq!(proposal.checkpoint_gate, Some(key));
    }

    #[test]
    fn retained_attachment_checks_data_without_authorizing_a_changed_role() {
        let voters = vec![NodeId([1; 32]), NodeId([2; 32]), NodeId([3; 32])];
        let prefix = RetainedAttachmentBarrier {
            committed: 33,
            last: 33,
            snapshot: 33,
            members: voters.clone(),
            joint_old: None,
            configuration: Some(0),
            retirement: None,
        };
        assert_eq!(prefix.validate_scope(&voters, 33), Ok(()));
        assert_eq!(prefix.validate_applied(&prefix, 33), Ok(()));
        let mutation = CommittedProposalBarrier {
            role: vos_raft::Role::Follower,
            term: 3,
            committed: 33,
            last: 33,
        };
        for role in [
            vos_raft::Role::PreCandidate,
            vos_raft::Role::Candidate,
            vos_raft::Role::Leader,
        ] {
            // Identical data permits transport setup, never a new operation
            // based on an earlier role/term sample.
            assert_eq!(prefix.validate_applied(&prefix, 33), Ok(()));
            assert_eq!(
                mutation.validate_applied(CommittedProposalBarrier { role, ..mutation }, 33),
                Err(SharedAgentHostError::Unavailable)
            );
        }
        assert_eq!(
            mutation.validate_applied(
                CommittedProposalBarrier {
                    term: 4,
                    ..mutation
                },
                33
            ),
            Err(SharedAgentHostError::Unavailable)
        );
        for changed in [
            RetainedAttachmentBarrier {
                last: 34,
                ..prefix.clone()
            },
            RetainedAttachmentBarrier {
                committed: 34,
                last: 34,
                ..prefix.clone()
            },
            RetainedAttachmentBarrier {
                snapshot: 32,
                ..prefix.clone()
            },
            RetainedAttachmentBarrier {
                members: voters[..2].to_vec(),
                ..prefix.clone()
            },
            RetainedAttachmentBarrier {
                joint_old: Some(voters.clone()),
                ..prefix.clone()
            },
            RetainedAttachmentBarrier {
                configuration: Some(32),
                ..prefix.clone()
            },
            RetainedAttachmentBarrier {
                retirement: Some(32),
                ..prefix.clone()
            },
        ] {
            assert_eq!(
                prefix.validate_applied(&changed, 33),
                Err(SharedAgentHostError::Unavailable)
            );
        }
        assert_eq!(
            prefix.validate_applied(&prefix, 32),
            Err(SharedAgentHostError::CorruptResidue)
        );
        assert_eq!(
            prefix.validate_scope(&voters, 32),
            Err(SharedAgentHostError::CorruptResidue)
        );
        assert_eq!(
            prefix.validate_scope(&voters[..2], 33),
            Err(SharedAgentHostError::ScopeMismatch)
        );
    }

    #[test]
    fn applied_availability_counts_only_distinct_admitted_voters() {
        let voters = [NodeId([1; 32]), NodeId([2; 32]), NodeId([3; 32])];
        let observer = NodeId([4; 32]);
        let mut available = BTreeSet::new();
        assert!(!has_applied_availability_quorum(&voters, &available));
        available.insert(voters[0]);
        assert!(!has_applied_availability_quorum(&voters, &available));
        available.insert(voters[0]);
        available.insert(observer);
        assert!(!has_applied_availability_quorum(&voters, &available));
        available.insert(voters[2]);
        assert!(has_applied_availability_quorum(&voters, &available));
        assert!(has_applied_availability_quorum(&voters[..1], &available));
        assert!(!has_applied_availability_quorum(&[], &available));
        assert!(!has_applied_availability_quorum(&voters[..2], &available));
        assert!(!has_applied_availability_quorum(
            &[voters[0]; 3],
            &available
        ));
        assert!(!has_applied_availability_quorum(
            &[NodeId::ZERO],
            &available
        ));
    }

    struct TempDatabase(std::path::PathBuf);

    impl TempDatabase {
        fn new(label: &str) -> Self {
            Self(std::env::temp_dir().join(format!(
                "vos_clean_agent_network_{label}_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
            )))
        }
    }

    impl Drop for TempDatabase {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn colliding_node(discriminator: u8) -> NodeId {
        let mut bytes = [0; 32];
        bytes[..2].copy_from_slice(&[0xa5, 0x5a]);
        bytes[31] = discriminator;
        NodeId(bytes)
    }

    fn initialize_database(path: &std::path::Path) -> Arc<Database> {
        let database = Arc::new(Database::create(path).unwrap());
        let transaction = database.begin_write().unwrap();
        {
            let _ = transaction.open_table(RAFT_META).unwrap();
            let _ = transaction.open_table(RAFT_LOG).unwrap();
        }
        transaction.commit().unwrap();
        database
    }

    // Component fixture: all quorum replies come from real fixed-voter
    // workers. It does not construct a public Shared host or claim startup
    // qualification. Gating delivery lets raw consensus progress be placed
    // precisely between the caller's existing admission barriers.
    struct RawWorkerTransport {
        local: NodeId,
        peers: Arc<std::sync::RwLock<BTreeMap<NodeId, vos_raft::WorkerHandle<NodeId>>>>,
        deliver: Arc<AtomicBool>,
    }

    impl RawWorkerTransport {
        fn peer(&self, peer: NodeId, sender: NodeId) -> Result<vos_raft::WorkerHandle<NodeId>, ()> {
            if sender != self.local || !self.deliver.load(Ordering::Acquire) {
                return Err(());
            }
            self.peers.read().unwrap().get(&peer).cloned().ok_or(())
        }
    }

    impl vos_raft::Transport<NodeId> for RawWorkerTransport {
        type Error = ();

        async fn send_append(
            &self,
            peer: NodeId,
            request: vos_raft::AppendEntriesReq<NodeId>,
        ) -> Result<vos_raft::AppendEntriesResp, ()> {
            Ok(self.peer(peer, request.leader)?
                .handle_authenticated_inbound_append(self.local, request).await)
        }

        async fn send_vote(
            &self,
            peer: NodeId,
            request: vos_raft::RequestVoteReq<NodeId>,
        ) -> Result<vos_raft::RequestVoteResp, ()> {
            Ok(self.peer(peer, request.candidate)?
                .handle_authenticated_inbound_vote(self.local, request).await)
        }

        async fn send_prevote(
            &self,
            peer: NodeId,
            request: vos_raft::PreVoteReq<NodeId>,
        ) -> Result<vos_raft::PreVoteResp, ()> {
            Ok(self.peer(peer, request.candidate)?
                .handle_authenticated_inbound_prevote(self.local, request).await)
        }

        async fn send_install(
            &self,
            peer: NodeId,
            request: vos_raft::InstallSnapshotReq<NodeId>,
        ) -> Result<vos_raft::InstallSnapshotResp, ()> {
            Ok(self.peer(peer, request.leader)?
                .handle_authenticated_inbound_install(self.local, request).await)
        }
    }

    struct RawWorkerCluster {
        // Workers join before their databases and owned files are dropped.
        _workers: Vec<vos_raft::Worker<NodeId>>,
        databases: BTreeMap<NodeId, Arc<Database>>,
        _paths: Vec<TempDatabase>,
        handles: BTreeMap<NodeId, vos_raft::WorkerHandle<NodeId>>,
        delivery: BTreeMap<NodeId, Arc<AtomicBool>>,
    }

    impl RawWorkerCluster {
        fn new(label: &str) -> Self {
            let manifest = crate::agent::shared_recovery::management_manifest_for_test();
            let voters = manifest.committee().members().iter()
                .map(|member| {
                    assert_eq!(member.replica().role, ReplicaRole::Voter);
                    member.replica().node
                }).collect::<Vec<_>>();
            assert_eq!(voters.len(), 3);
            let peers = Arc::new(std::sync::RwLock::new(BTreeMap::new()));
            let mut cluster = Self {
                _workers: Vec::new(), databases: BTreeMap::new(), _paths: Vec::new(),
                handles: BTreeMap::new(), delivery: BTreeMap::new(),
            };
            for node in &voters {
                let path = TempDatabase::new(label);
                let database = initialize_database(&path.0);
                let deliver = Arc::new(AtomicBool::new(true));
                let transport = Arc::new(RawWorkerTransport {
                    local: *node, peers: Arc::clone(&peers), deliver: Arc::clone(&deliver),
                });
                let mut config = vos_raft::Config::new(*node, voters.clone(), [0x72; 32]);
                config.max_append_entries = MAX_SHARED_RAFT_APPEND_ENTRIES;
                let worker = vos_raft::Worker::try_spawn(
                    AgentNodeStorage::open(Arc::clone(&database), (0, 0)).unwrap(),
                    transport, config, None,
                ).unwrap();
                worker.wait_init().unwrap();
                let handle = worker.handler();
                peers.write().unwrap().insert(*node, handle.clone());
                cluster._workers.push(worker);
                cluster.databases.insert(*node, database);
                cluster._paths.push(path);
                cluster.handles.insert(*node, handle);
                cluster.delivery.insert(*node, deliver);
            }
            cluster
        }

        fn settled_leader(&self) -> (NodeId, vos_raft::WorkerSnapshot<NodeId>) {
            let deadline = Instant::now() + ORDERED_REPLY_WAIT;
            loop {
                for (node, handle) in &self.handles {
                    let snapshot = futures_executor::block_on(handle.snapshot()).unwrap();
                    if snapshot.role == vos_raft::Role::Leader
                        && snapshot.last_log_index > 0
                        && snapshot.commit_index == snapshot.last_log_index
                    {
                        let settled = self.handles.iter().all(|(peer, handle)| {
                            if peer == node { return true; }
                            let follower = futures_executor::block_on(handle.snapshot()).unwrap();
                            follower.role == vos_raft::Role::Follower
                                && follower.current_term == snapshot.current_term
                                && follower.last_log_index == snapshot.last_log_index
                                && follower.commit_index == snapshot.commit_index
                                && follower.leader_hint == Some(*node)
                        });
                        let current = futures_executor::block_on(handle.snapshot()).unwrap();
                        if settled && CommittedProposalBarrier::from(&current)
                            == CommittedProposalBarrier::from(&snapshot)
                        {
                            return (*node, current);
                        }
                    }
                }
                assert!(Instant::now() < deadline, "fixed-three worker election did not settle");
                std::thread::yield_now();
            }
        }

        fn isolate(&self) {
            for deliver in self.delivery.values() {
                deliver.store(false, Ordering::Release);
            }
        }

        fn last_term(&self, node: NodeId, index: u64) -> u64 {
            RaftLog::open(Arc::clone(&self.databases[&node])).unwrap()
                .term_at(index).unwrap().unwrap()
        }
    }

    fn signed_management_race_commands() -> (shared_raft::AgentRaftCommand, shared_raft::AgentRaftCommand) {
        use crate::agent::shared_commit::ReplicaCommitSignature;
        use ed25519_dalek::{Signer as _, SigningKey};

        let manifest = crate::agent::shared_recovery::completed_management_manifest_for_test();
        let owner = crate::agent::shared_recovery::management_node_for_test(1);
        let slot = manifest.management_slot(owner).unwrap();
        let registration = slot.registration().clone();
        registration.verify(manifest.generation(), manifest.committee()).unwrap();
        let request = SharedManagementRecoveryReleaseRequest::for_slot(slot).unwrap();
        let signature = ReplicaCommitSignature::new(owner,
            SigningKey::from_bytes(&[1; 32]).sign(&request.signing_message().0).to_bytes()).unwrap();
        let release = SharedManagementRecoveryRelease::new(request, signature).unwrap();
        release.verify(manifest.generation(), manifest.committee()).unwrap();
        let scope = manifest.generation();
        let route = shared_raft::AgentRouteKey::new(scope.space(), scope.agent(), scope.genesis(),
            scope.admission(), manifest.committee().id()).unwrap();
        let registration = shared_raft::AgentRaftCommand::RegisterManagementRecovery { route, registration };
        let release = shared_raft::AgentRaftCommand::ReleaseManagementRecovery { route, release };
        registration.validate().unwrap();
        release.validate().unwrap();
        (registration, release)
    }

    #[test]
    fn raw_worker_progress_after_preflight_invalidates_each_proposal_barrier_field() {
        let cluster = RawWorkerCluster::new("raw_preflight_progress");
        let (local, mut before) = cluster.settled_leader();
        cluster.isolate();
        let handle = &cluster.handles[&local];
        let sender = *cluster.handles.keys().find(|node| **node != local).unwrap();
        let (_, release) = signed_management_race_commands();

        for change in 0..4 {
            // Raft RPCs carry authenticated identities, not signature fields.
            // The appended application payload is a genuinely signed release.
            let term = before.current_term + u64::from(change == 1);
            let entry = (change == 2).then(|| LogEntry::data(
                before.last_log_index + 1, term, release.encode()));
            let response = futures_executor::block_on(handle.handle_authenticated_inbound_append(
                sender, vos_raft::AppendEntriesReq {
                    leader: sender, term, prev_log_index: before.last_log_index,
                    prev_log_term: cluster.last_term(local, before.last_log_index),
                    leader_commit: if change == 3 { before.last_log_index } else { before.commit_index },
                    entries: entry.into_iter().collect(),
                },
            ));
            assert!(response.success);
            let current = futures_executor::block_on(handle.snapshot()).unwrap();
            match change {
                0 => {
                    assert_eq!(before.role, vos_raft::Role::Leader);
                    assert_eq!(current.role, vos_raft::Role::Follower);
                    assert_eq!(current.current_term, before.current_term);
                }
                1 => {
                    assert_eq!(current.role, before.role);
                    assert_eq!(current.current_term, before.current_term + 1);
                }
                2 => assert_eq!(current.last_log_index, before.last_log_index + 1),
                3 => assert_eq!(current.commit_index, before.commit_index + 1),
                _ => unreachable!(),
            }
            if change != 2 { assert_eq!(current.last_log_index, before.last_log_index); }
            if change != 3 { assert_eq!(current.commit_index, before.commit_index); }
            if change >= 2 {
                assert_eq!(current.role, before.role);
                assert_eq!(current.current_term, before.current_term);
            }
            // The capacity frontier may still be old or already drained to the
            // newer commit. Both invalidate this sampled preflight; neither
            // is classified as stable-store corruption. These are component
            // barrier cases: the later follower samples are not actual leader
            // release preflights, and custody needs the separate host fixture.
            for applied in [before.commit_index, current.commit_index] {
                assert_eq!(CommittedProposalBarrier::from(&before).validate_applied(
                    CommittedProposalBarrier::from(&current), applied),
                    Err(SharedAgentHostError::Unavailable));
            }
            assert!(matches!(futures_executor::block_on(handle.propose_if_prefix(
                release.encode(), before.current_term, before.last_log_index, before.commit_index)),
                Err(vos_raft::ProposeError::PrefixChanged)));
            assert_eq!(futures_executor::block_on(handle.snapshot()).unwrap(), current);
            before = current;
        }
    }

    #[test]
    fn raw_worker_progress_before_publish_refuses_stale_signed_management_prefix() {
        let cluster = RawWorkerCluster::new("raw_publish_progress");
        let (local, final_snapshot) = cluster.settled_leader();
        cluster.isolate();
        let handle = &cluster.handles[&local];
        let (registration, release) = signed_management_race_commands();
        assert_eq!(CommittedProposalBarrier::from(&final_snapshot).validate_applied(
            CommittedProposalBarrier::from(&final_snapshot), final_snapshot.commit_index), Ok(()));

        // Another raw proposal lands after the final host snapshot. The actual
        // worker CAS must refuse before appending the release, independently
        // of the earlier host/proposal guards.
        let index = futures_executor::block_on(handle.propose(registration.encode())).unwrap();
        let after_append = futures_executor::block_on(handle.snapshot()).unwrap();
        assert_eq!(index, final_snapshot.last_log_index + 1);
        assert_eq!(after_append.role, final_snapshot.role);
        assert_eq!(after_append.current_term, final_snapshot.current_term);
        assert_eq!(after_append.commit_index, final_snapshot.commit_index);
        let refuse = |prefix: &vos_raft::WorkerSnapshot<NodeId>| {
            let before = futures_executor::block_on(handle.snapshot()).unwrap();
            assert!(matches!(futures_executor::block_on(handle.propose_if_prefix(
                release.encode(), prefix.current_term, prefix.last_log_index, prefix.commit_index)),
                Err(vos_raft::ProposeError::PrefixChanged)));
            assert_eq!(futures_executor::block_on(handle.snapshot()).unwrap(), before);
        };
        refuse(&final_snapshot);

        // Real peers acknowledge that same row, changing only the commit
        // frontier. A snapshot from before quorum commitment is still stale.
        cluster.delivery[&local].store(true, Ordering::Release);
        let deadline = Instant::now() + ORDERED_REPLY_WAIT;
        let committed = loop {
            let snapshot = futures_executor::block_on(handle.snapshot()).unwrap();
            assert_eq!(snapshot.role, vos_raft::Role::Leader);
            assert_eq!(snapshot.current_term, after_append.current_term);
            assert_eq!(snapshot.last_log_index, after_append.last_log_index);
            if snapshot.commit_index == index { break snapshot; }
            assert!(Instant::now() < deadline, "fixed-three raw proposal did not commit");
            std::thread::yield_now();
        };
        cluster.isolate();
        refuse(&after_append);
        let log = RaftLog::open(Arc::clone(&cluster.databases[&local])).unwrap();
        let entries = log.entries(index, index).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(shared_raft::decode_agent_raft_entry_kind(&entries[0].payload).unwrap(),
            EntryKind::Data { payload: registration.encode() });

        // The same release is admissible to the worker with the fresh exact
        // committed prefix, so malformed payloads are not causing refusal.
        let released_at = futures_executor::block_on(handle.propose_if_prefix(
            release.encode(), committed.current_term, committed.last_log_index,
            committed.commit_index)).unwrap();
        assert_eq!(released_at, index + 1);
        let entries = log.entries(released_at, released_at).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(shared_raft::decode_agent_raft_entry_kind(&entries[0].payload).unwrap(),
            EntryKind::Data { payload: release.encode() });
    }

    #[test]
    fn promotion_deadline_consults_serialized_state_and_requires_full_commit() {
        let snapshot = |role, committed| (role, committed, 1);
        // The atomic hint can still expose Candidate while an in-flight
        // worker event finishes promotion. Only the serialized reply is final.
        let result = system_promotion_barrier(
            || vos_raft::Role::Candidate,
            || Some(snapshot(vos_raft::Role::Leader, 1)),
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(result, 1);
        for (role, committed) in [
            (vos_raft::Role::Candidate, 1),
            (vos_raft::Role::Follower, 1),
            (vos_raft::Role::Leader, 0),
        ] {
            assert!(matches!(
                system_promotion_barrier(
                    || vos_raft::Role::Candidate,
                    || Some(snapshot(role, committed)),
                    Duration::ZERO,
                ),
                Err(SharedAgentHostError::Unavailable)
            ));
        }
        assert!(matches!(
            system_promotion_barrier(|| vos_raft::Role::Leader, || None, Duration::ZERO),
            Err(SharedAgentHostError::Unavailable)
        ));
    }

    #[test]
    fn already_staged_merge_object_does_not_reenter_physical_storage() {
        assert!(!merge_object_needs_staging(&SharedMergeObject::Staged(
            vec![0x41]
        )));
        assert!(!merge_object_needs_staging(&SharedMergeObject::Published(
            vec![0x42]
        )));
        assert!(merge_object_needs_staging(&SharedMergeObject::Missing));
    }

    #[test]
    fn full_node_storage_keeps_colliding_votes_and_configuration_across_restart() {
        let path = TempDatabase::new("full_node_restart");
        let database = initialize_database(&path.0);
        let first = colliding_node(1);
        let second = colliding_node(2);
        assert_eq!(&first.as_bytes()[..2], &second.as_bytes()[..2]);
        assert_ne!(first, second);
        let mut members = vec![second, first];
        members.sort_unstable();

        let mut storage = AgentNodeStorage::open(Arc::clone(&database), (0, 0)).unwrap();
        futures_executor::block_on(storage.commit_batch(WriteBatch {
            appends: vec![LogEntry {
                index: 1,
                term: 1,
                kind: EntryKind::Data {
                    payload: vec![0x11],
                },
            }],
            meta: Some(Meta {
                current_term: 1,
                voted_for: Some(first),
                commit_index: 1,
                snap_last_index: 0,
                snap_last_term: 0,
            }),
            active_config: Some(ActiveConfigRecord {
                log_index: Some(1),
                current: members.clone(),
                joint_old: None,
            }),
            ..WriteBatch::default()
        }))
        .unwrap();

        // Simulate the journal application transaction advancing its cursor
        // between two independent worker commits.
        let transaction = database.begin_write().unwrap();
        let mut host_meta = RaftMeta::load_from_write_transaction(&transaction).unwrap();
        host_meta.last_applied = 1;
        host_meta.write_host_fields_in_txn(&transaction).unwrap();
        transaction.commit().unwrap();

        futures_executor::block_on(storage.commit_batch(WriteBatch {
            appends: vec![LogEntry {
                index: 2,
                term: 2,
                kind: EntryKind::Data {
                    payload: vec![0x22],
                },
            }],
            meta: Some(Meta {
                current_term: 2,
                voted_for: Some(second),
                commit_index: 2,
                snap_last_index: 0,
                snap_last_term: 0,
            }),
            active_config: Some(ActiveConfigRecord {
                log_index: Some(2),
                current: members.clone(),
                joint_old: Some(vec![first]),
            }),
            ..WriteBatch::default()
        }))
        .unwrap();
        drop(storage);

        let mut reopened = AgentNodeStorage::open(Arc::clone(&database), (0, 0)).unwrap();
        let meta = futures_executor::block_on(reopened.load_meta()).unwrap();
        assert_eq!(meta.current_term, 2);
        assert_eq!(meta.voted_for, Some(second));
        assert_eq!(meta.commit_index, 2);
        assert_eq!(
            futures_executor::block_on(reopened.applied_index()).unwrap(),
            Some(1)
        );
        assert_eq!(
            futures_executor::block_on(reopened.active_config()).unwrap(),
            Some(ActiveConfigRecord {
                log_index: Some(2),
                current: members,
                joint_old: Some(vec![first]),
            })
        );
        assert!(
            futures_executor::block_on(reopened.commit_batch(WriteBatch {
                state: Some(vec![1]),
                ..WriteBatch::default()
            }))
            .is_err()
        );
        drop(reopened);

        // A legacy compact vote row makes the clean storage refuse reopen;
        // it is never interpreted as either colliding full identity.
        let transaction = database.begin_write().unwrap();
        let mut legacy = RaftMeta::load_from_write_transaction(&transaction).unwrap();
        legacy.voted_for = Some(0x5aa5);
        legacy.write_worker_fields_in_txn(&transaction).unwrap();
        transaction.commit().unwrap();
        assert!(AgentNodeStorage::open(database, (0, 0)).is_err());

        let legacy_config_path = TempDatabase::new("legacy_config");
        let legacy_config_database = initialize_database(&legacy_config_path.0);
        let transaction = legacy_config_database.begin_write().unwrap();
        {
            let mut table = transaction.open_table(RAFT_META).unwrap();
            table
                .insert(META_LEGACY_ACTIVE_CONFIG, b"compact".as_slice())
                .unwrap();
        }
        transaction.commit().unwrap();
        assert!(AgentNodeStorage::open(legacy_config_database, (0, 0)).is_err());
    }

    #[test]
    fn full_node_storage_accepts_only_the_authenticated_snapshot_boundary() {
        let path = TempDatabase::new("authenticated_snapshot_restart");
        let database = initialize_database(&path.0);
        let transaction = database.begin_write().unwrap();
        let mut meta = RaftMeta::load_from_write_transaction(&transaction).unwrap();
        meta.current_term = 3;
        meta.commit_index = 7;
        meta.last_applied = 7;
        meta.snap_last_index = 7;
        meta.snap_last_term = 2;
        meta.write_worker_fields_in_txn(&transaction).unwrap();
        meta.write_host_fields_in_txn(&transaction).unwrap();
        transaction.commit().unwrap();

        assert!(AgentNodeStorage::open(Arc::clone(&database), (0, 0)).is_err());
        assert!(AgentNodeStorage::open(Arc::clone(&database), (7, 3)).is_err());
        let mut storage = AgentNodeStorage::open(Arc::clone(&database), (7, 2)).unwrap();
        let recovered = futures_executor::block_on(storage.load_meta()).unwrap();
        assert_eq!(recovered.snap_last_index, 7);
        assert_eq!(recovered.snap_last_term, 2);
        assert_eq!(storage.last_index(), 7);
        assert_eq!(storage.last_term(), 2);

        assert!(
            futures_executor::block_on(storage.commit_batch(WriteBatch {
                meta: Some(Meta {
                    current_term: 3,
                    voted_for: None,
                    commit_index: 7,
                    snap_last_index: 0,
                    snap_last_term: 0,
                }),
                ..WriteBatch::default()
            }))
            .is_err()
        );
        futures_executor::block_on(storage.commit_batch(WriteBatch {
            appends: vec![LogEntry {
                index: 8,
                term: 3,
                kind: EntryKind::Data {
                    payload: vec![0x41],
                },
            }],
            meta: Some(Meta {
                current_term: 3,
                voted_for: None,
                commit_index: 8,
                snap_last_index: 7,
                snap_last_term: 2,
            }),
            ..WriteBatch::default()
        }))
        .unwrap();
        drop(storage);

        let reopened = AgentNodeStorage::open(database, (7, 2)).unwrap();
        let meta = futures_executor::block_on(reopened.load_meta()).unwrap();
        assert_eq!((meta.snap_last_index, meta.snap_last_term), (7, 2));
        assert_eq!(meta.commit_index, 8);
        assert_eq!(reopened.last_index(), 8);
    }

    #[test]
    fn ordered_reply_waiters_are_exactly_keyed_under_concurrent_delivery() {
        let waiters = Arc::new(OrderedReplyWaiters::default());
        let first = ReplayInputId([1; 32]);
        let second = ReplayInputId([2; 32]);
        waiters.register(first).unwrap();
        waiters.register(second).unwrap();
        assert_eq!(waiters.register(first), Err(AgentHandlerError));

        let barrier = Arc::new(Barrier::new(3));
        let spawn_waiter = |input| {
            let waiters = Arc::clone(&waiters);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                waiters.wait(input)
            })
        };
        let first_waiter = spawn_waiter(first);
        let second_waiter = spawn_waiter(second);
        barrier.wait();

        let first_outcome =
            RuntimeOutcome::Completed(Err(vos_agent_sdk::InvocationError::NotFound));
        let second_outcome =
            RuntimeOutcome::Completed(Err(vos_agent_sdk::InvocationError::StaleDeployment));
        {
            let mut replies = waiters.replies.lock().unwrap();
            // Deliberately publish in reverse order: neither caller may
            // consume or overwrite the other invocation's outcome.
            replies.insert(second, OrderedReplyState::Ready(second_outcome.clone()));
            replies.insert(first, OrderedReplyState::Ready(first_outcome.clone()));
        }
        waiters.changed.notify_all();
        assert_eq!(first_waiter.join().unwrap(), Ok(first_outcome));
        assert_eq!(second_waiter.join().unwrap(), Ok(second_outcome));
        assert!(waiters.replies.lock().unwrap().is_empty());
    }

    #[test]
    fn rejected_stale_activation_releases_its_read_lease_before_retirement() {
        let lifecycle = RwLock::new(true);
        let stale = AtomicBool::new(true);
        assert!(acquire_route_activation(&lifecycle, &stale).is_none());
        assert!(
            lifecycle.try_write().is_ok(),
            "stale activation cleanup must be able to acquire the exclusive retirement lease"
        );

        stale.store(false, Ordering::Release);
        *lifecycle.write().unwrap() = false;
        assert!(acquire_route_activation(&lifecycle, &stale).is_none());
        assert!(lifecycle.try_write().is_ok());
    }

    #[test]
    fn fixed_three_reattachment_defers_only_implicit_system_promotion() {
        let claim = crate::agent::shared_commit::common_snapshot_claim_for_test();
        let members = claim
            .active_committee()
            .members()
            .iter()
            .map(|member| {
                (
                    NodeId(member.replica().node.0),
                    PeerId::from_bytes(member.peer_id()).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let voters = members.iter().map(|(node, _)| *node).collect();
        let base = AttachmentFingerprint {
            protocol_route: AgentGenerationRoute {
                space: vos_agent_sdk::SpaceId(claim.ordered().space().0),
                agent: vos_agent_sdk::AgentId(claim.ordered().agent().0),
                generation: Hash([3; 32]),
            },
            durable_route: shared_raft::AgentRouteKey::new(
                claim.ordered().space(),
                claim.ordered().agent(),
                claim.ordered().genesis(),
                claim.ordered().admission(),
                claim.ordered().committee(),
            )
            .unwrap(),
            members,
            voters,
            next_committee: None,
            next_voters: None,
            joint_old: None,
            local_role: ReplicaRole::Voter,
        };
        assert!(!base.requires_promotion_barrier(false, true, false, false));
        for required in 0..3 {
            assert!(base.requires_promotion_barrier(
                required == 0,
                true,
                required == 1,
                required == 2,
            ));
        }
        for invalid in 0..6 {
            let mut changed = base.clone();
            match invalid {
                0 => {
                    changed.members.truncate(1);
                    changed.voters.truncate(1);
                }
                1 => changed.joint_old = Some(changed.voters.clone()),
                2 => changed.next_committee = Some(claim.active_committee().id()),
                3 => changed.next_voters = Some(changed.voters.clone()),
                4 => changed.local_role = ReplicaRole::Observer,
                5 => {
                    changed.voters.pop();
                }
                _ => unreachable!(),
            }
            assert!(
                changed.requires_promotion_barrier(false, true, false, false),
                "shape {invalid}"
            );
            assert!(!changed.requires_promotion_barrier(false, false, false, false));
        }
    }

    #[test]
    fn attachment_fingerprint_distinguishes_role_membership_and_joint_config() {
        let local_peer = libp2p::identity::Keypair::ed25519_from_bytes([31; 32])
            .unwrap()
            .public()
            .to_peer_id();
        let local = NodeId::of_authenticated_peer(&local_peer.to_bytes());
        let other_peer = libp2p::identity::Keypair::ed25519_from_bytes([32; 32])
            .unwrap()
            .public()
            .to_peer_id();
        let other = NodeId::of_authenticated_peer(&other_peer.to_bytes());
        let mut members = vec![(local, local_peer), (other, other_peer)];
        members.sort_unstable_by_key(|(node, _)| *node);
        let mut voters = vec![local, other];
        voters.sort_unstable();
        let fingerprint = AttachmentFingerprint {
            protocol_route: AgentGenerationRoute {
                space: vos_agent_sdk::SpaceId([1; 32]),
                agent: vos_agent_sdk::AgentId([2; 32]),
                generation: Hash([3; 32]),
            },
            durable_route: shared_raft::AgentRouteKey::new(
                crate::service::SpaceId([1; 32]),
                crate::service::AgentId([2; 32]),
                crate::agent::journal::AgentJournalGenesisId([4; 32]),
                crate::agent::genesis::AgentGenesisAdmissionId::from_bytes([5; 32]),
                crate::agent::genesis::AgentReplicaCommitteeId::from_bytes([6; 32]),
            )
            .unwrap(),
            members,
            next_committee: None,
            next_voters: None,
            voters,
            joint_old: None,
            local_role: ReplicaRole::Voter,
        };
        assert!(fingerprint.validates_local(local));
        assert!(fingerprint.owns_raft_worker(local));

        let mut changed = fingerprint.clone();
        changed.joint_old = Some(vec![local]);
        assert_ne!(changed, fingerprint);
        let mut changed = fingerprint.clone();
        changed.next_committee = Some(crate::agent::genesis::AgentReplicaCommitteeId::from_bytes(
            [7; 32],
        ));
        assert_ne!(changed, fingerprint);
        assert!(!changed.validates_local(local));
        let mut changed = fingerprint.clone();
        changed.local_role = ReplicaRole::Observer;
        assert_ne!(changed, fingerprint);
        assert!(!changed.validates_local(local));
        assert!(changed.owns_raft_worker(local));
        changed.voters.retain(|node| *node != local);
        assert!(changed.validates_local(local));
        assert!(!changed.owns_raft_worker(local));

        let mut promoted = changed;
        promoted.next_committee = Some(crate::agent::genesis::AgentReplicaCommitteeId::from_bytes(
            [8; 32],
        ));
        promoted.next_voters = Some(vec![local]);
        assert!(promoted.validates_local(local));
        assert!(
            promoted.owns_raft_worker(local),
            "a promoted observer must receive the joint entry as a follower"
        );
    }
}
