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
use crate::agent::shared_commit::SharedAgentSnapshotCertificate;
use crate::agent::shared_host::{
    SharedAgentApplyOutcome, SharedAgentHost, SharedAgentHostError, SharedAgentRuntimeProjection,
    SharedAgentStatus, SharedAgentTransportState,
};
use crate::agent::shared_journal_driver::SharedMergeObject;
use crate::agent::{ReplicaRole, shared_raft};
use crate::commit::CommitError;
use crate::raft::{RAFT_META, RaftLog, RaftMeta};
use crate::service::wire::ServiceWire;

use super::Network;
use super::agent_network::{AGENT_REQUEST_TIMEOUT, AgentHandlerError, AgentRouteHandler};
use super::agent_protocol::{
    AgentGenerationRoute, AgentMessage, AuthenticatedAgentFrame, InvocationRedirect,
    InvocationReply, MergeMessage, RaftLogEntryKind, RaftMessage, RaftRole, RaftStatus,
    RaftVotePhase, invocation_request_correlation,
};
use super::agent_raft_transport::AgentRaftTransport;

const META_AGENT_VOTED_FOR: &str = "agent_node_voted_for_v1";
const META_AGENT_ACTIVE_CONFIG: &str = "agent_node_active_config_v1";
const META_LEGACY_ACTIVE_CONFIG: &str = "active_config";
const ACTIVE_CONFIG_MAGIC: &[u8; 4] = b"ANC1";
const MAX_AGENT_VOTERS: usize = crate::agent::MAX_AGENT_REPLICAS;
const MAX_PENDING_ORDERED_REPLIES: usize = 1_024;
const MAX_MERGE_SYNC_SCAN_EVENTS: usize = MAX_REPLAY_SUFFIX_ENTRIES + MAX_MERGE_FRONTIER_ENTRIES;
const MAX_MERGE_SYNC_EVENTS: usize = MAX_IMPORT_EVENTS;
const MAX_MERGE_SYNC_BYTES: usize = MAX_IMPORT_BYTES;
const ORDERED_REPLY_WAIT: Duration = Duration::from_millis(1_800);

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
        let result = (|| -> Result<(), CommitError> {
            let transaction = self.database.begin_write()?;
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
            transaction.commit()?;
            Ok(())
        })();
        if let Err(error) = result {
            self.log.cache_restore(cache);
            return Err(error);
        }
        Ok(())
    }
}

fn protocol_route(status: &SharedAgentStatus) -> AgentGenerationRoute {
    protocol_route_from(status.generation, status.replication_id)
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

fn route_members(
    status: &SharedAgentStatus,
) -> Result<Vec<(NodeId, PeerId)>, SharedAgentHostError> {
    route_members_from(&status.replicas, status.committee_transition.as_ref())
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

fn raft_configuration(status: &SharedAgentStatus) -> (Vec<NodeId>, Option<Vec<NodeId>>) {
    raft_configuration_from(&status.replicas, status.committee_transition.as_ref())
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
        let mut replies = self.replies.lock().map_err(|_| AgentHandlerError)?;
        loop {
            match replies.get(&input) {
                Some(OrderedReplyState::Ready(_)) => {
                    let Some(OrderedReplyState::Ready(outcome)) = replies.remove(&input) else {
                        unreachable!("reply state was checked while holding the same lock")
                    };
                    return Ok(outcome);
                }
                Some(OrderedReplyState::Failed) | None => {
                    replies.remove(&input);
                    return Err(AgentHandlerError);
                }
                Some(OrderedReplyState::Waiting) => {}
            }
            let now = Instant::now();
            if now >= deadline {
                replies.remove(&input);
                return Err(AgentHandlerError);
            }
            let (next, timeout) = self
                .changed
                .wait_timeout(replies, deadline.saturating_duration_since(now))
                .map_err(|_| AgentHandlerError)?;
            replies = next;
            if timeout.timed_out()
                && matches!(replies.get(&input), Some(OrderedReplyState::Waiting))
            {
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
    fn from_status(status: &SharedAgentStatus) -> Result<Self, SharedAgentHostError> {
        let members = route_members(status)?;
        let (voters, joint_old) = raft_configuration(status);
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
            protocol_route: protocol_route(status),
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
    worker: Option<vos_raft::WorkerHandle<NodeId>>,
    proposal: Mutex<ProposalAdmission>,
    ordered_replies: Arc<OrderedReplyWaiters>,
    lifecycle: Arc<RwLock<bool>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProjectionPairKey {
    invocation: crate::agent_sdk::InvocationId,
    work: Hash,
    authorization: Hash,
}

impl ProjectionPairKey {
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
) -> Result<[ProjectionPairKey; 2], SharedAgentHostError> {
    let key = |envelope: &crate::agent_sdk::RuntimeWork| {
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
        Ok(ProjectionPairKey::new(invocation, authorization))
    };
    let keys = [key(envelopes[0])?, key(envelopes[1])?];
    if keys[0].invocation == keys[1].invocation {
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    Ok(keys)
}

#[derive(Default)]
struct ProposalAdmission {
    projection_pair: Option<ProjectionPairKey>,
    management_retirement: Option<Vec<[ProjectionPairKey; 2]>>,
}

fn management_retirement_set_keys(
    agent: crate::service::AgentId,
    pairs: &[[&crate::agent_sdk::RuntimeWork; 2]],
) -> Result<Vec<[ProjectionPairKey; 2]>, SharedAgentHostError> {
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
        self.projection_pair.is_some() || self.management_retirement.is_some()
    }
}

#[derive(Clone, Copy)]
enum ReservedSubmission {
    Projection(ProjectionPairKey),
    ManagementRetirement(ProjectionPairKey),
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
    ReservedProjection,
    ReservedManagementRetirement,
    PersistedManagement(&'a crate::agent::clean_management_intent::ManagementJournalAnchor),
}

struct RecoveringProjectionAdmission<'a> {
    agent: crate::service::AgentId,
    work: &'a InvocationWork,
    authorization: &'a InvocationAuthorization,
    expected_committee: &'a AgentReplicaCommittee,
    signer: &'a dyn LocalMergeAuthenticator,
}

/// Result of one authenticated clean Ordered submission through the live
/// Raft worker. `new_slot == false` is possible only when the bounded durable
/// journal suffix proved the exact request was already committed.
pub(crate) struct CleanOrderedSubmission {
    pub(crate) input: ReplayInputId,
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

impl SharedRouteHandler {
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

    fn reserve_projection_pair(
        &self,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        recovering: bool,
    ) -> Result<(), SharedAgentHostError> {
        let key = ProjectionPairKey::new(work, authorization);
        let mut proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if proposal.management_retirement.is_some() {
            return Err(SharedAgentHostError::Conflict);
        }
        match proposal.projection_pair {
            Some(existing) if existing == key => return Ok(()),
            Some(_) => return Err(SharedAgentHostError::Conflict),
            None => {}
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
        let status = host
            .show(self.agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if status.applied_slots != barrier.commit_index {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        let Some(required) =
            host.projection_admission_requirement(self.agent, work, authorization, recovering)?
        else {
            return Err(SharedAgentHostError::CapacityExhausted);
        };
        // Keep one physical slot beyond every non-empty exact lifecycle.
        // A crash can leave its final record committed while the next
        // one-voter reopen must still append the mandatory current-term
        // leader no-op before recovery may publish the route.
        let required_with_reopen = (required as u64).saturating_add(u64::from(required != 0));
        if status.remaining_slots < required_with_reopen {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        proposal.projection_pair = Some(key);
        Ok(())
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
        if host
            .show(self.agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .applied_slots
            != barrier.commit_index
        {
            return Err(SharedAgentHostError::CorruptResidue);
        }
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

    fn reserve_management_retirement_set(
        &self,
        pairs: &[[&crate::agent_sdk::RuntimeWork; 2]],
    ) -> Result<(), SharedAgentHostError> {
        let keys = management_retirement_set_keys(self.agent, pairs)?;
        let mut proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if proposal.projection_pair.is_some() {
            return Err(SharedAgentHostError::Conflict);
        }
        match &proposal.management_retirement {
            Some(existing) if keys.iter().all(|pair| existing.contains(pair)) => return Ok(()),
            Some(_) => return Err(SharedAgentHostError::Conflict),
            None => {}
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
        let status = host
            .show(self.agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if status.applied_slots != barrier.commit_index {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        let required = host
            .management_retirement_set_admission_requirement(
                self.agent,
                &pairs.iter().flatten().copied().collect::<Vec<_>>(),
            )?
            .ok_or(SharedAgentHostError::CapacityExhausted)?;
        if status.remaining_slots < required as u64 + u64::from(required != 0) {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        proposal.management_retirement = Some(keys);
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
            || proposal.projection_pair.is_some()
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
            Some(_) => Err(SharedAgentHostError::Conflict),
        }
    }

    fn release_projection_pair(
        &self,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
    ) -> Result<(), SharedAgentHostError> {
        let key = ProjectionPairKey::new(work, authorization);
        let mut proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if proposal.projection_pair != Some(key) {
            return Err(SharedAgentHostError::Conflict);
        }
        proposal.projection_pair = None;
        Ok(())
    }

    fn complete_projection_pair<F>(
        &self,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        complete: F,
    ) -> Result<(), SharedAgentHostError>
    where
        F: FnOnce() -> Result<(), SharedAgentHostError>,
    {
        let key = ProjectionPairKey::new(work, authorization);
        let mut proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if proposal.projection_pair != Some(key) {
            return Err(SharedAgentHostError::Conflict);
        }
        // Keep every suffix-consuming ingress path excluded through the
        // durable pending-record clear. A failed clear leaves the exact key
        // reserved; a successful clear and volatile release are one critical
        // section, so neither an ingress gap nor an unrecoverable post-clear
        // release failure exists.
        complete()?;
        proposal.projection_pair = None;
        Ok(())
    }

    fn reserve_checkpoint_gate(
        &self,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
    ) -> Result<(), SharedAgentHostError> {
        let key = ProjectionPairKey::new(work, authorization);
        let mut proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if proposal.management_retirement.is_some() {
            return Err(SharedAgentHostError::Conflict);
        }
        match proposal.projection_pair {
            None => proposal.projection_pair = Some(key),
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

    fn submit_reserved_clean_ordered_operation(
        &self,
        request: crate::agent::shared_journal_driver::CleanInvocationReplayRequest,
        terminal_only: bool,
    ) -> Result<CleanOrderedSubmission, SharedAgentHostError> {
        let key = ProjectionPairKey::new(request.work(), request.authorization());
        self.submit_clean_ordered_operation_with_admission(
            request,
            terminal_only,
            Some(ReservedSubmission::Projection(key)),
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
        let proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        match (proposal.projection_pair, &proposal.management_retirement, reservation) {
            (None, None, None) => {}
            (Some(expected), None, Some(ReservedSubmission::Projection(actual))) if expected == actual => {}
            (None, Some(expected), Some(ReservedSubmission::ManagementRetirement(actual)))
                if expected.iter().any(|pair| pair.contains(&actual))
                    && matches!(&request, crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Acknowledge { .. }) => {}
            _ => return Err(SharedAgentHostError::CapacityExhausted),
        }
        let worker = self
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if !self.has_local_proposer(worker) {
            return Err(SharedAgentHostError::Unavailable);
        }
        let anchor_barrier = if matches!(clock, InvocationClock::PersistedManagement(_)) {
            let barrier = futures_executor::block_on(worker.snapshot())
                .ok_or(SharedAgentHostError::Unavailable)?;
            if barrier.role != vos_raft::Role::Leader
                || barrier.commit_index != barrier.last_log_index
            {
                return Err(SharedAgentHostError::Unavailable);
            }
            Some(barrier.commit_index)
        } else {
            None
        };
        let input = {
            let mut host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            drain_committed(&mut host, self.agent, &self.ordered_replies)?;
            let anchored_input = if let InvocationClock::PersistedManagement(anchor) = clock {
                if host
                    .show(self.agent)?
                    .ok_or(SharedAgentHostError::AgentNotFound)?
                    .applied_slots
                    != anchor_barrier.unwrap()
                {
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
                let required = host
                    .management_pending_admission_requirement(self.agent, &[(anchor, &envelope)])?
                    .ok_or(SharedAgentHostError::CapacityExhausted)?;
                if host
                    .show(self.agent)?
                    .ok_or(SharedAgentHostError::AgentNotFound)?
                    .remaining_slots
                    < required as u64 + 1
                {
                    return Err(SharedAgentHostError::CapacityExhausted);
                }
                Some(host.management_invocation_after_anchor(self.agent, anchor, &envelope)?)
            } else {
                None
            };
            let prepared = if matches!(clock, InvocationClock::Bootstrap) {
                host.prepare_bootstrap_invocation(self.agent, request)?
            } else if matches!(clock, InvocationClock::PersistedManagement(_)) {
                host.prepare_persisted_management_invocation(self.agent, request)?
            } else if matches!(reservation, Some(ReservedSubmission::Projection(_))) {
                host.prepare_reserved_projection_operation(self.agent, request, terminal_only)?
            } else if terminal_only {
                host.prepare_terminal_clean_ordered_operation(self.agent, request)?
            } else {
                host.prepare_clean_ordered_operation(self.agent, request)?
            };
            let input = prepared.input();
            if let Some(observed) = anchored_input {
                // Preparation must agree with the authenticated interval. A
                // result predating a substituted late anchor is not a retry
                // proved by that anchor, even if another cache can find it.
                if observed != prepared.retained().map(|_| input) {
                    return Err(SharedAgentHostError::CorruptResidue);
                }
            }
            if let Some(outcome) = prepared.retained().cloned() {
                return Ok(CleanOrderedSubmission {
                    input,
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
            if futures_executor::block_on(worker.propose(payload)).is_err() {
                self.ordered_replies.cancel(input);
                return Err(SharedAgentHostError::Unavailable);
            }
            input
        };
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, self.agent, &self.ordered_replies)?;
        drop(host);
        let outcome = self
            .ordered_replies
            .wait(input)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        Ok(CleanOrderedSubmission {
            input,
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
                    let prepared = host
                        .prepare_clean_ordered(self.agent, work.clone(), authorization)
                        .map_err(|_| AgentHandlerError)?;
                    if let Some(outcome) = prepared.retained().cloned() {
                        return Ok(reply_for_outcome(correlation, outcome));
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
        // Imported Merge events consume the same authenticated composite
        // suffix budget as the reserved projection pair. Hold admission for
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
        match frame.message {
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
    // System attachments always serialize leader promotion and drain the
    // recovered physical suffix before publishing a route. Keep that
    // identity across refresh/checkpoint reattachment, not just bootstrap.
    system_agents: BTreeSet<crate::service::AgentId>,
    // Exact pending envelopes outlive a volatile route/worker generation.
    // Startup callers must seed these from independently verified durable
    // lifecycle stores before any system route is activated.
    management_retirements:
        BTreeMap<crate::service::AgentId, Vec<[crate::agent_sdk::RuntimeWork; 2]>>,
    #[cfg(test)]
    force_checkpoint_once: bool,
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
    pub fn attach(
        host: Arc<Mutex<SharedAgentHost>>,
        network: Arc<Network>,
    ) -> Result<Self, SharedAgentHostError> {
        Self::attach_internal(host, network, None, None, None)
    }

    /// Attach the one-voter clean system Agent. With no durable pending
    /// projection, checkpoint before a mandatory leader no-op could combine
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
        Self::attach_internal(host, network, None, Some(agent), None)
    }

    /// Reopen a system host with the exact durable pending projection pair
    /// already excluded before its route is activated. No ingress or Merge
    /// pump can consume replay headroom in the attach-to-recovery window.
    pub(crate) fn attach_recovering_projection(
        host: Arc<Mutex<SharedAgentHost>>,
        network: Arc<Network>,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
    ) -> Result<Self, SharedAgentHostError> {
        if crate::service::AgentId(work.agent.0) != agent || !authorization.matches_work(work) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        Self::attach_internal(
            host,
            network,
            Some(RecoveringProjectionAdmission {
                agent,
                work,
                authorization,
                expected_committee,
                signer,
            }),
            Some(agent),
            None,
        )
    }

    /// Restore an independently verified pending retirement before publishing
    /// the system route. Unlike Query recovery, do not checkpoint away missing
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
        if pairs.is_empty() || pairs.len() > MAX_REPLAY_SUFFIX_ENTRIES / 2 {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        management_retirement_set_keys(agent, &retirement_pair_refs(&pairs))?;
        Self::attach_internal(host, network, None, Some(agent), Some((agent, pairs)))
    }

    fn attach_internal<'a>(
        host: Arc<Mutex<SharedAgentHost>>,
        network: Arc<Network>,
        recovering: Option<RecoveringProjectionAdmission<'a>>,
        promotion_barrier: Option<crate::service::AgentId>,
        retirement: Option<(
            crate::service::AgentId,
            Vec<[crate::agent_sdk::RuntimeWork; 2]>,
        )>,
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
            #[cfg(test)]
            force_checkpoint_once: false,
            #[cfg(test)]
            fail_reattach_once: false,
        };
        for status in statuses {
            if status.local_role.is_some() {
                let pending = recovering
                    .as_ref()
                    .filter(|pending| pending.agent == status.generation.agent())
                    .map(|pending| pending);
                let barrier =
                    pending.is_some() || promotion_barrier == Some(status.generation.agent());
                attachment.attach_status(status, pending, barrier)?;
            }
        }
        if recovering
            .as_ref()
            .is_some_and(|pending| !attachment.generations.contains_key(&pending.agent))
        {
            return Err(SharedAgentHostError::AgentNotFound);
        }
        if attachment
            .management_retirements
            .keys()
            .any(|agent| !attachment.generations.contains_key(agent))
        {
            return Err(SharedAgentHostError::AgentNotFound);
        }
        Ok(attachment)
    }

    fn install_detached_projection_checkpoint(
        host: &mut SharedAgentHost,
        recovering: &RecoveringProjectionAdmission<'_>,
    ) -> Result<(), SharedAgentHostError> {
        Self::install_detached_checkpoint(
            host,
            recovering.agent,
            recovering.expected_committee,
            recovering.signer,
        )
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
    /// status before any projection capacity decision. This also closes the
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

    pub(crate) fn reserve_projection_pair(
        &mut self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        recovering: bool,
    ) -> Result<(), SharedAgentHostError> {
        if crate::service::AgentId(work.agent.0) != agent || !authorization.matches_work(work) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if recovering {
            let stale = self
                .generations
                .get(&agent)
                .is_some_and(|attached| attached.stale.load(Ordering::Acquire));
            if stale {
                self.retire(agent)?;
            }
            if !self.generations.contains_key(&agent) {
                return Err(SharedAgentHostError::TransportNotAttached);
            }
        } else {
            self.ensure_reattached(agent)?;
        }
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        attached
            .coordinator
            .reserve_projection_pair(work, authorization, recovering)
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
            return Err(SharedAgentHostError::Conflict);
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

    pub(crate) fn reserve_recovering_projection_pair(
        &mut self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
    ) -> Result<(), SharedAgentHostError> {
        if crate::service::AgentId(work.agent.0) != agent || !authorization.matches_work(work) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let stale = self
            .generations
            .get(&agent)
            .is_some_and(|attached| attached.stale.load(Ordering::Acquire));
        if stale {
            self.retire(agent)?;
        }
        if !self.generations.contains_key(&agent) {
            let status = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .show(agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?;
            let recovering = RecoveringProjectionAdmission {
                agent,
                work,
                authorization,
                expected_committee,
                signer,
            };
            self.attach_status(status, Some(&recovering), true)?;
        }
        self.reserve_projection_pair(agent, work, authorization, true)
    }

    pub(crate) fn release_projection_pair(
        &self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
    ) -> Result<(), SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        attached
            .coordinator
            .release_projection_pair(work, authorization)
    }

    pub(crate) fn complete_projection_pair<F>(
        &self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        complete: F,
    ) -> Result<(), SharedAgentHostError>
    where
        F: FnOnce() -> Result<(), SharedAgentHostError>,
    {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        attached
            .coordinator
            .complete_projection_pair(work, authorization, complete)
    }

    /// Install a quorum-authenticated journal checkpoint before the bounded
    /// Ordered suffix can strand a projection Invoke/Ack pair. Clean system
    /// Agents are structurally one local voter; every other committee shape
    /// fails closed rather than manufacturing a partial certificate.
    pub(crate) fn certified_checkpoint_for_projection_pair(
        &mut self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
    ) -> Result<bool, SharedAgentHostError> {
        self.ensure_reattached(agent)?;
        let (raft_fits, replay_fits) = {
            let host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let status = host
                .show(agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?;
            let required = host.projection_admission_records(agent, work, authorization, false)?;
            (
                status.remaining_slots
                    >= (required as u64).saturating_add(u64::from(required != 0)),
                host.projection_pair_fits(agent, work, authorization)?,
            )
        };
        #[cfg(test)]
        let forced = core::mem::take(&mut self.force_checkpoint_once);
        #[cfg(not(test))]
        let forced = false;
        if !forced && raft_fits && replay_fits {
            return Ok(false);
        }
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
                        .release_projection_pair(work, authorization);
                    return Err(error);
                }
            };
            if candidate.claim().active_committee() != expected_committee {
                drop(host);
                let _ = attached
                    .coordinator
                    .release_projection_pair(work, authorization);
                return Err(SharedAgentHostError::SnapshotCertificateInvalid);
            }
            let Some(signature) = signer.sign_snapshot_candidate(&candidate) else {
                drop(host);
                let _ = attached
                    .coordinator
                    .release_projection_pair(work, authorization);
                return Err(SharedAgentHostError::SnapshotCertificateInvalid);
            };
            match SharedAgentSnapshotCertificate::new(candidate.claim().clone(), vec![signature]) {
                Ok(certificate) => certificate,
                Err(_) => {
                    drop(host);
                    let _ = attached
                        .coordinator
                        .release_projection_pair(work, authorization);
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
            (Ok(_), Ok(())) => {
                let host = self
                    .host
                    .lock()
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
                let remaining = host
                    .show(agent)?
                    .ok_or(SharedAgentHostError::AgentNotFound)?
                    .remaining_slots;
                let required = host
                    .projection_admission_requirement(agent, work, authorization, false)?
                    .ok_or(SharedAgentHostError::CapacityExhausted)?;
                if remaining < (required as u64).saturating_add(u64::from(required != 0))
                    || !host.projection_pair_fits(agent, work, authorization)?
                {
                    return Err(SharedAgentHostError::CapacityExhausted);
                }
                Ok(true)
            }
            (Err(error), Ok(())) => Err(error),
            (_, Err(error)) => Err(error),
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
        self.attach_status(status, None, false)
    }

    #[cfg(test)]
    pub(crate) fn force_checkpoint_once_for_test(&mut self) {
        self.force_checkpoint_once = true;
    }

    #[cfg(test)]
    pub(crate) fn fail_reattach_once_for_test(&mut self) {
        self.fail_reattach_once = true;
    }

    fn attach_status(
        &mut self,
        status: SharedAgentStatus,
        recovering: Option<&RecoveringProjectionAdmission<'_>>,
        promotion_barrier: bool,
    ) -> Result<(), SharedAgentHostError> {
        self.attach_status_with_recovery_checkpoint(status, recovering, promotion_barrier, true)
    }

    fn attach_status_with_recovery_checkpoint(
        &mut self,
        status: SharedAgentStatus,
        recovering: Option<&RecoveringProjectionAdmission<'_>>,
        promotion_barrier: bool,
        allow_checkpoint: bool,
    ) -> Result<(), SharedAgentHostError> {
        let agent = status.generation.agent();
        let retirement = self.management_retirements.get(&agent).cloned();
        if retirement.is_some() && recovering.is_some() {
            return Err(SharedAgentHostError::Conflict);
        }
        let promotion_barrier =
            promotion_barrier || self.system_agents.contains(&agent) || retirement.is_some();
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
        if let Some(envelopes) = &retirement {
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
            let remaining = host
                .show(agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?
                .remaining_slots;
            // The new one-voter worker must append its current-term no-op.
            if remaining < required as u64 + 1 {
                return Err(SharedAgentHostError::CapacityExhausted);
            }
        }
        if let Some(recovering) = recovering {
            let (required, remaining) = {
                let host = self
                    .host
                    .lock()
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
                let status = host
                    .show(agent)?
                    .ok_or(SharedAgentHostError::AgentNotFound)?;
                (
                    host.projection_admission_requirement(
                        agent,
                        recovering.work,
                        recovering.authorization,
                        true,
                    )?,
                    status.remaining_slots,
                )
            };
            let needs_checkpoint = required.is_none_or(|required| {
                remaining
                    < u64::try_from(required)
                        .unwrap_or(u64::MAX)
                        .saturating_add(1)
            });
            if needs_checkpoint {
                if !allow_checkpoint {
                    return Err(SharedAgentHostError::CapacityExhausted);
                }
                drop(reservation);
                {
                    let mut host = self
                        .host
                        .lock()
                        .map_err(|_| SharedAgentHostError::Unavailable)?;
                    Self::install_detached_projection_checkpoint(&mut host, recovering)?;
                }
                let status = self
                    .host
                    .lock()
                    .map_err(|_| SharedAgentHostError::Unavailable)?
                    .show(agent)?
                    .ok_or(SharedAgentHostError::AgentNotFound)?;
                return self.attach_status_with_recovery_checkpoint(
                    status,
                    Some(recovering),
                    promotion_barrier,
                    false,
                );
            }
        }
        let fingerprint = AttachmentFingerprint::from_attachment_status(&attachment_status)?;
        let local = self.network.agent_node_id();
        if !fingerprint.validates_local(local) {
            return Err(SharedAgentHostError::ScopeMismatch);
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
        let (mut worker, handle, receiver) = if fingerprint.owns_raft_worker(local) {
            let database = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .raft_database(agent)?;
            let storage = AgentNodeStorage::open(database, authenticated_snapshot)
                .map_err(|_| SharedAgentHostError::CorruptResidue)?;
            let transport = Arc::new(AgentRaftTransport::new(Arc::clone(&self.network), route));
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
            if host
                .show(agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?
                .applied_slots
                != committed
            {
                return Err(SharedAgentHostError::CorruptResidue);
            }
        }
        if let Some(recovering) = recovering {
            let (required, remaining) = {
                let host = self
                    .host
                    .lock()
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
                let status = host
                    .show(agent)?
                    .ok_or(SharedAgentHostError::AgentNotFound)?;
                (
                    host.projection_admission_requirement(
                        agent,
                        recovering.work,
                        recovering.authorization,
                        true,
                    )?,
                    status.remaining_slots,
                )
            };
            let capacity = required
                .is_some_and(|required| remaining >= u64::try_from(required).unwrap_or(u64::MAX));
            if !capacity {
                if let Some(worker) = worker.take() {
                    worker.shutdown();
                }
                drop(handle);
                drop(receiver);
                drop(reservation);
                if !allow_checkpoint {
                    return Err(SharedAgentHostError::CapacityExhausted);
                }
                {
                    let mut host = self
                        .host
                        .lock()
                        .map_err(|_| SharedAgentHostError::Unavailable)?;
                    Self::install_detached_projection_checkpoint(&mut host, recovering)?;
                }
                let status = self
                    .host
                    .lock()
                    .map_err(|_| SharedAgentHostError::Unavailable)?
                    .show(agent)?
                    .ok_or(SharedAgentHostError::AgentNotFound)?;
                return self.attach_status_with_recovery_checkpoint(
                    status,
                    Some(recovering),
                    promotion_barrier,
                    false,
                );
            }
        }
        let lifecycle = Arc::new(RwLock::new(true));
        let apply_worker = handle.clone();
        let initial_admission = if let Some(recovering) = recovering {
            let host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let status = host
                .show(agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?;
            let Some(required) = host.projection_admission_requirement(
                agent,
                recovering.work,
                recovering.authorization,
                true,
            )?
            else {
                return Err(SharedAgentHostError::CapacityExhausted);
            };
            if status.remaining_slots < required as u64 {
                return Err(SharedAgentHostError::CapacityExhausted);
            }
            ProposalAdmission {
                projection_pair: Some(ProjectionPairKey::new(
                    recovering.work,
                    recovering.authorization,
                )),
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
            let remaining = host
                .show(agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?
                .remaining_slots;
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
        let handler_impl = Arc::new(SharedRouteHandler {
            host: Arc::clone(&self.host),
            network: Arc::clone(&self.network),
            route,
            agent,
            route_nodes: fingerprint.members.iter().map(|(node, _)| *node).collect(),
            worker: handle,
            proposal: Mutex::new(initial_admission),
            ordered_replies: Arc::clone(&ordered_replies),
            lifecycle: Arc::clone(&lifecycle),
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
                        if drain_committed(&mut host, agent, &ordered_replies).is_err() {
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
            .list()?;
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
            let fingerprint = AttachmentFingerprint::from_status(&status)?;
            let rebuild = self.generations.get(&agent).is_some_and(|attached| {
                attached.stale.load(Ordering::Acquire) || attached.fingerprint != fingerprint
            });
            if rebuild {
                self.retire(agent)?;
            }
            if !self.generations.contains_key(&agent) {
                self.attach_status(status, None, false)?;
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
        self.refresh()?;
        let agents = self.generations.keys().copied().collect::<Vec<_>>();
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
        self.refresh()?;
        let leased_agents = self.generations.keys().copied().collect::<Vec<_>>();
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
        let audit = host.audit_authority_projection(head, projected, root)?;
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
        if work.mode != crate::agent_sdk::MethodMode::Linear
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

    pub(crate) fn supervisor_invoke_terminal_reserved(
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
            SupervisorAdmission::ReservedProjection,
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

    pub(crate) fn supervisor_acknowledge_reserved(
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
            SupervisorAdmission::ReservedProjection,
        )
    }

    fn supervisor_invocation_operation(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        request: crate::agent::shared_journal_driver::CleanInvocationReplayRequest,
        terminal_only: bool,
        admission: SupervisorAdmission<'_>,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        let work = request.work();
        if matches!(admission, SupervisorAdmission::ReservedManagementRetirement)
            && (work.mode != MethodMode::Linear
                || !matches!(&request, crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Acknowledge { .. }))
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let authorization = request.authorization();
        let agent = crate::service::AgentId(work.agent.0);
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        // Keep the same lifecycle -> host order as the network route handler.
        // `retire` releases its host guard before requesting the write lease.
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        {
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
                if matches!(admission, SupervisorAdmission::ReservedManagementRetirement) =>
            {
                let key = ProjectionPairKey::new(request.work(), request.authorization());
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
            InvocationScope::Ordered
                if matches!(admission, SupervisorAdmission::ReservedProjection) =>
            {
                self.invoke_reserved_clean_operation(agent, request, terminal_only)
                    .map(|submission| submission.outcome)
            }
            InvocationScope::Ordered if terminal_only => self
                .invoke_terminal_clean_operation(agent, request)
                .map(|submission| submission.outcome),
            InvocationScope::Ordered => self
                .invoke_clean_operation(agent, request)
                .map(|submission| submission.outcome),
            InvocationScope::Merge => self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .apply_clean_merge_operation(agent, request),
            InvocationScope::Local => self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .apply_clean_local_operation(agent, request),
        }
    }

    /// Submit an exact clean ordered invocation through the generation's
    /// authenticated one-owner Raft proposer and synchronous apply path.
    pub(crate) fn invoke_clean(
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
            .submit_clean_ordered(work, authorization)
    }

    /// Internal root bootstrap only; ordinary routed calls retain their exact
    /// caller-supplied authorization and use `invoke_clean`.
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

    fn invoke_clean_operation(
        &self,
        agent: crate::service::AgentId,
        request: crate::agent::shared_journal_driver::CleanInvocationReplayRequest,
    ) -> Result<CleanOrderedSubmission, SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        attached.coordinator.submit_clean_ordered_operation(request)
    }

    fn invoke_terminal_clean_operation(
        &self,
        agent: crate::service::AgentId,
        request: crate::agent::shared_journal_driver::CleanInvocationReplayRequest,
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
            .submit_terminal_clean_ordered_operation(request)
    }

    fn invoke_reserved_clean_operation(
        &self,
        agent: crate::service::AgentId,
        request: crate::agent::shared_journal_driver::CleanInvocationReplayRequest,
        terminal_only: bool,
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
            .submit_reserved_clean_ordered_operation(request, terminal_only)
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

    #[cfg(test)]
    pub(crate) fn attachment_for_test(
        &self,
        agent: crate::service::AgentId,
    ) -> Option<(Arc<dyn AgentRouteHandler>, bool)> {
        self.generations
            .get(&agent)
            .map(|attached| (Arc::clone(&attached.handler), attached.worker.is_some()))
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
