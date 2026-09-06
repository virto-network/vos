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
use vos_agent_sdk::{Hash, MethodMode, NodeId, RuntimeOutcome};
use vos_raft::{ActiveConfigRecord, EntryKind, LogEntry, Meta, Storage, WriteBatch};

use crate::agent::journal::{
    CanonicalJournalRecord, MAX_IMPORT_BYTES, MAX_IMPORT_EVENTS, MAX_JOURNAL_RECORD_BYTES,
    MAX_MERGE_FRONTIER_ENTRIES, MAX_REPLAY_SUFFIX_BYTES, MAX_REPLAY_SUFFIX_ENTRIES, MergeEvent,
    MergeEventId, ReplayInputId,
};
use crate::agent::shared_host::{
    SharedAgentApplyOutcome, SharedAgentHost, SharedAgentHostError, SharedAgentStatus,
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
}

impl AgentNodeStorage {
    fn open(database: Arc<Database>) -> Result<Self, CommitError> {
        let log = RaftLog::open(Arc::clone(&database))?;
        let meta = RaftMeta::load(&database)?;
        if meta.voted_for.is_some() || meta.snap_last_index != 0 || meta.snap_last_term != 0 {
            return Err(storage_error(
                "legacy vote or unauthenticated snapshot in clean Agent Raft database",
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
        let storage = Self { database, log };
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
            || durable.snap_last_index != 0
            || durable.snap_last_term != 0
        {
            return Err(storage_error("non-clean Agent Raft metadata"));
        }
        Ok(Meta {
            current_term: durable.current_term,
            voted_for: self.load_exact_vote()?,
            commit_index: durable.commit_index,
            snap_last_index: 0,
            snap_last_term: 0,
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
                if meta.snap_last_index != 0
                    || meta.snap_last_term != 0
                    || meta.commit_index > self.log.last_index()
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
                    snap_last_index: 0,
                    snap_last_term: 0,
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
    AgentGenerationRoute {
        space: vos_agent_sdk::SpaceId(status.generation.space().0),
        agent: vos_agent_sdk::AgentId(status.generation.agent().0),
        generation: Hash(status.replication_id),
    }
}

fn route_members(
    status: &SharedAgentStatus,
) -> Result<Vec<(NodeId, PeerId)>, SharedAgentHostError> {
    let mut by_node = BTreeMap::new();
    let replicas = status.replicas.iter().chain(
        status
            .committee_transition
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
    let active = voter_nodes(&status.replicas);
    match &status.committee_transition {
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
    proposal: Mutex<()>,
    ordered_replies: Arc<OrderedReplyWaiters>,
    lifecycle: Arc<RwLock<bool>>,
}

impl SharedRouteHandler {
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
                let _proposal = self.proposal.lock().map_err(|_| AgentHandlerError)?;
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
                    let input = prepared.input();
                    self.ordered_replies.register(input)?;
                    if futures_executor::block_on(worker.propose(prepared.into_payload())).is_err()
                    {
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
                let outcome = self
                    .host
                    .lock()
                    .map_err(|_| AgentHandlerError)?
                    .apply_clean_merge(self.agent, work, authorization)
                    .map_err(|_| AgentHandlerError)?;
                Ok(reply_for_outcome(correlation, outcome))
            }
            MethodMode::LocalQuery | MethodMode::Local => {
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
        let statuses = host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .list()?;
        let mut attachment = Self {
            host,
            network,
            generations: BTreeMap::new(),
        };
        for status in statuses {
            if status.local_role.is_some() {
                attachment.attach_status(status)?;
            }
        }
        Ok(attachment)
    }

    fn attach_status(&mut self, mut status: SharedAgentStatus) -> Result<(), SharedAgentHostError> {
        let agent = status.generation.agent();
        if self.generations.contains_key(&agent) {
            return Err(SharedAgentHostError::Conflict);
        }
        let mut reservation = TransportAttachReservation::reserve(Arc::clone(&self.host), agent)?;
        let ordered_replies = Arc::new(OrderedReplyWaiters::default());
        // Recovery may reopen a database with durable commit_index ahead of
        // the journal application cursor. No new Raft event is guaranteed to
        // arrive, so drain that exact suffix before exposing a route or
        // deriving its current committee fingerprint.
        {
            let mut host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            drain_committed(&mut host, agent, &ordered_replies)?;
            status = host
                .show(agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?;
        }
        let fingerprint = AttachmentFingerprint::from_status(&status)?;
        let local = self.network.agent_node_id();
        if !fingerprint.validates_local(local) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let route = fingerprint.protocol_route;
        let (mut worker, handle, receiver) = if fingerprint.owns_raft_worker(local) {
            let database = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .raft_database(agent)?;
            let storage = AgentNodeStorage::open(database)
                .map_err(|_| SharedAgentHostError::CorruptResidue)?;
            let transport = Arc::new(AgentRaftTransport::new(Arc::clone(&self.network), route));
            let mut config =
                vos_raft::Config::new(local, fingerprint.voters.clone(), status.replication_id);
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
        let lifecycle = Arc::new(RwLock::new(true));
        let apply_worker = handle.clone();
        let handler_impl = Arc::new(SharedRouteHandler {
            host: Arc::clone(&self.host),
            network: Arc::clone(&self.network),
            route,
            agent,
            route_nodes: fingerprint.members.iter().map(|(node, _)| *node).collect(),
            worker: handle,
            proposal: Mutex::new(()),
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
                        let current =
                            host.show(agent).ok().flatten().and_then(|status| {
                                AttachmentFingerprint::from_status(&status).ok()
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
                self.attach_status(status)?;
            }
        }
        Ok(())
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

        let mut storage = AgentNodeStorage::open(Arc::clone(&database)).unwrap();
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

        let mut reopened = AgentNodeStorage::open(Arc::clone(&database)).unwrap();
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
        assert!(AgentNodeStorage::open(database).is_err());

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
        assert!(AgentNodeStorage::open(legacy_config_database).is_err());
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
