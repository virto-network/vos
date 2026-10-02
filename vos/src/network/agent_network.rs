//! Swarm attachment and exact routing for the clean Agent protocol.
//!
//! This module deliberately shares no routing or reply state with the legacy
//! `/vos/0.1.0` behaviour.  A complete Noise-authenticated [`PeerId`] is
//! converted to a clean [`NodeId`] before a route directory, member set, or
//! handler is consulted.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::sync::{Arc, Mutex, mpsc as std_mpsc};
use std::time::Duration;

use crate::agent::shared_commit::{ReplicaCommitSignature, SharedAgentCommonSnapshotClaim};
use crate::agent::shared_raft::AgentRaftCommand;
use futures_channel::oneshot;
use libp2p::request_response::{self, Message};
use libp2p::{PeerId, Swarm};
use tokio::sync::OwnedSemaphorePermit;
use tracing::{debug, warn};
use vos_agent_sdk::{Hash, NodeId};

use super::agent_protocol::{
    AgentFrame, AgentGenerationRoute, AgentMessage, AgentProtocolError, AppliedAvailabilityRequest,
    AuthenticatedAgentFrame, AuthorityReadBarrier, AuthorityReadBarrierRequest,
    ForwardedSharedInstallRequest, InvocationRedirect, InvocationReply, InvocationRequest,
    MAX_RAFT_MEMBERS, ManagementRecoveryOperationRequest, MergeMessage, RaftMessage, RaftStatus,
    RaftVotePhase, authenticate_sender, invocation_request_correlation, outcome_matches_work,
};
use super::{Network, NetworkCmd, VosBehaviour};

#[cfg(all(
    target_os = "linux",
    feature = "storage",
    feature = "experimental-state-blocks"
))]
mod shared_fixture;

/// Agent consensus traffic has its own bounded timeout.  It must not inherit
/// the legacy service invocation's five-minute extension budget.
pub(super) const AGENT_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
/// Global hard cap on authenticated clean-Agent handler jobs per Network.
/// Admission happens before `spawn_blocking`, so a route member cannot create
/// an unbounded Tokio blocking queue or an unbounded set of generation leases.
pub(super) const MAX_AGENT_INBOUND_HANDLERS: usize = 256;
const MAX_AGENT_INBOUND_RAFT_HANDLERS: usize = 64;
const MAX_AGENT_INBOUND_AVAILABILITY_HANDLERS: usize = 32;
const MAX_AGENT_INBOUND_APPLICATION_HANDLERS: usize = MAX_AGENT_INBOUND_HANDLERS
    - MAX_AGENT_INBOUND_RAFT_HANDLERS
    - MAX_AGENT_INBOUND_AVAILABILITY_HANDLERS;
/// Global hard cap spanning clean-Agent commands waiting in the network
/// mailbox and requests already tracked by libp2p.  A permit is acquired
/// before an outbound frame is prepared and is released only when that exact
/// request completes, fails, or is dropped during network shutdown.
pub(super) const MAX_AGENT_OUTBOUND_REQUESTS: usize = 256;
const MAX_AGENT_OUTBOUND_RAFT_REQUESTS: usize = 64;
const MAX_AGENT_OUTBOUND_AVAILABILITY_REQUESTS: usize = 32;
const MAX_AGENT_OUTBOUND_APPLICATION_REQUESTS: usize = MAX_AGENT_OUTBOUND_REQUESTS
    - MAX_AGENT_OUTBOUND_RAFT_REQUESTS
    - MAX_AGENT_OUTBOUND_AVAILABILITY_REQUESTS;
const _: () = assert!(
    MAX_AGENT_INBOUND_APPLICATION_HANDLERS
        + MAX_AGENT_INBOUND_RAFT_HANDLERS
        + MAX_AGENT_INBOUND_AVAILABILITY_HANDLERS
        == MAX_AGENT_INBOUND_HANDLERS
);
const _: () = assert!(
    MAX_AGENT_OUTBOUND_APPLICATION_REQUESTS
        + MAX_AGENT_OUTBOUND_RAFT_REQUESTS
        + MAX_AGENT_OUTBOUND_AVAILABILITY_REQUESTS
        == MAX_AGENT_OUTBOUND_REQUESTS
);
/// A prepared/joint transition routes the union of two independently bounded
/// committees even though each physical Raft configuration remains capped at
/// `MAX_RAFT_MEMBERS`.
const MAX_AGENT_ROUTE_MEMBERS: usize = MAX_RAFT_MEMBERS * 2;

/// Stable reasons a typed clean Agent request did not complete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AgentNetworkError {
    InvalidRoute,
    InvalidMembership,
    RouteAlreadyRegistered,
    NodeIdentityMismatch { claimed: NodeId, derived: NodeId },
    NodeAlreadyBound(NodeId),
    PeerAlreadyBound(PeerId),
    UnknownRoute(AgentGenerationRoute),
    UnknownMember(NodeId),
    UnknownDestination(NodeId),
    InvalidRequestKind,
    InvalidRequest(AgentProtocolError),
    ResponseSenderMismatch,
    ResponsePeerMismatch,
    ResponseRouteMismatch,
    ResponseTypeMismatch,
    ResponseCorrelationMismatch,
    OutboundCapacity,
    Timeout,
    Disconnected,
    UnsupportedProtocol,
    Transport,
}

impl fmt::Display for AgentNetworkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRoute => formatter.write_str("invalid clean Agent route"),
            Self::InvalidMembership => formatter.write_str("invalid clean Agent route membership"),
            Self::RouteAlreadyRegistered => {
                formatter.write_str("clean Agent route is already registered")
            }
            Self::NodeIdentityMismatch { claimed, derived } => write!(
                formatter,
                "clean Agent node {claimed:?} does not match PeerId-derived {derived:?}"
            ),
            Self::NodeAlreadyBound(node) => {
                write!(formatter, "clean Agent node {node:?} is already bound")
            }
            Self::PeerAlreadyBound(peer) => {
                write!(formatter, "Noise peer {peer} is already bound")
            }
            Self::UnknownRoute(route) => write!(formatter, "unknown clean Agent route {route:?}"),
            Self::UnknownMember(node) => {
                write!(
                    formatter,
                    "node {node:?} is not a member of the clean Agent route"
                )
            }
            Self::UnknownDestination(node) => {
                write!(
                    formatter,
                    "no exact Noise destination for clean Agent node {node:?}"
                )
            }
            Self::InvalidRequestKind => formatter.write_str("invalid clean Agent request kind"),
            Self::InvalidRequest(error) => {
                write!(formatter, "invalid clean Agent request: {error}")
            }
            Self::ResponseSenderMismatch => {
                formatter.write_str("clean Agent response sender does not match destination")
            }
            Self::ResponsePeerMismatch => {
                formatter.write_str("clean Agent response PeerId does not match destination")
            }
            Self::ResponseRouteMismatch => {
                formatter.write_str("clean Agent response route does not match request")
            }
            Self::ResponseTypeMismatch => {
                formatter.write_str("clean Agent response type does not match request")
            }
            Self::ResponseCorrelationMismatch => {
                formatter.write_str("clean Agent response correlation does not match request")
            }
            Self::OutboundCapacity => {
                formatter.write_str("clean Agent outbound request capacity exhausted")
            }
            Self::Timeout => formatter.write_str("clean Agent request timed out"),
            Self::Disconnected => formatter.write_str("clean Agent destination disconnected"),
            Self::UnsupportedProtocol => {
                formatter.write_str("peer does not support /vos/agent/3.0.0")
            }
            Self::Transport => formatter.write_str("clean Agent transport failure"),
        }
    }
}

impl std::error::Error for AgentNetworkError {}

/// A route handler is invoked only after full-PeerId sender authentication,
/// exact route lookup, and full-NodeId membership authorization succeed.
pub(crate) trait AgentRouteHandler: Send + Sync + 'static {
    fn handle(&self, request: AuthenticatedAgentFrame) -> Result<AgentMessage, AgentHandlerError>;
}

/// Handler refusal has no wire representation.  The request is deliberately
/// left unanswered and the caller receives a bounded transport timeout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AgentHandlerError;

pub(super) struct AgentRouteRegistration {
    members: Vec<NodeId>,
    handler: Arc<dyn AgentRouteHandler>,
}

impl AgentRouteRegistration {
    fn contains(&self, node: NodeId) -> bool {
        self.members.binary_search(&node).is_ok()
    }
}

pub(super) type AgentRouteDirectory =
    Arc<Mutex<BTreeMap<AgentGenerationRoute, Arc<AgentRouteRegistration>>>>;

#[derive(Default)]
pub(super) struct AgentPeerBindings {
    by_node: BTreeMap<NodeId, PeerId>,
    by_peer: HashMap<PeerId, NodeId>,
    pinned: BTreeSet<NodeId>,
    owners: BTreeMap<NodeId, BTreeSet<AgentGenerationRoute>>,
}

pub(super) type AgentPeerDirectory = Arc<Mutex<AgentPeerBindings>>;

pub(super) fn new_agent_peer_directory(local_peer: PeerId) -> AgentPeerDirectory {
    let local_node = NodeId::of_authenticated_peer(&local_peer.to_bytes());
    Arc::new(Mutex::new(AgentPeerBindings {
        by_node: BTreeMap::from([(local_node, local_peer)]),
        by_peer: HashMap::from([(local_peer, local_node)]),
        pinned: BTreeSet::from([local_node]),
        owners: BTreeMap::new(),
    }))
}

fn bind_peer(
    directory: &AgentPeerDirectory,
    claimed: NodeId,
    peer: PeerId,
) -> Result<(), AgentNetworkError> {
    let derived = NodeId::of_authenticated_peer(&peer.to_bytes());
    if claimed == NodeId::ZERO || claimed != derived {
        return Err(AgentNetworkError::NodeIdentityMismatch { claimed, derived });
    }
    let Ok(mut bindings) = directory.lock() else {
        return Err(AgentNetworkError::Transport);
    };
    if let Some(bound) = bindings.by_node.get(&claimed) {
        return if *bound == peer {
            Ok(())
        } else {
            Err(AgentNetworkError::NodeAlreadyBound(claimed))
        };
    }
    if let Some(bound) = bindings.by_peer.get(&peer) {
        return if *bound == claimed {
            Ok(())
        } else {
            Err(AgentNetworkError::PeerAlreadyBound(peer))
        };
    }
    bindings.by_node.insert(claimed, peer);
    bindings.by_peer.insert(peer, claimed);
    bindings.pinned.insert(claimed);
    Ok(())
}

fn resolve_peer(directory: &AgentPeerDirectory, node: NodeId) -> Option<PeerId> {
    let bindings = directory.lock().ok()?;
    let peer = *bindings.by_node.get(&node)?;
    (bindings.by_peer.get(&peer) == Some(&node)).then_some(peer)
}

fn valid_route_members(members: &[NodeId]) -> bool {
    !members.is_empty()
        && members.len() <= MAX_AGENT_ROUTE_MEMBERS
        && members.iter().all(|node| *node != NodeId::ZERO)
        && members.windows(2).all(|pair| pair[0] < pair[1])
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AgentInvocationResponse {
    Reply(InvocationReply),
    Redirect(InvocationRedirect),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AgentRaftAppendResponse {
    pub(crate) term: u64,
    pub(crate) success: bool,
    pub(crate) match_index: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AgentRaftVoteResponse {
    pub(crate) term: u64,
    pub(crate) granted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AgentRaftInstallSnapshotResponse {
    pub(crate) term: u64,
    pub(crate) bytes_received: u64,
}

#[derive(Clone, Copy)]
pub(super) struct PendingMeta {
    route: AgentGenerationRoute,
    target_node: NodeId,
    target_peer: PeerId,
}

pub(super) enum PendingAgentReply {
    AuthorityReadBarrier {
        meta: PendingMeta,
        request: Hash,
        reply: std_mpsc::Sender<Result<Option<AuthorityReadBarrier>, AgentNetworkError>>,
    },
    ForwardedSharedInstall {
        meta: PendingMeta,
        request: Hash,
        package_len: u64,
        reply: std_mpsc::Sender<Result<Option<u64>, AgentNetworkError>>,
    },
    ManagementRecoveryCommand {
        meta: PendingMeta,
        command: Hash,
        reply: std_mpsc::Sender<Result<bool, AgentNetworkError>>,
    },
    ManagementRecoveryOperation {
        meta: PendingMeta,
        request: Hash,
        reply: std_mpsc::Sender<Result<bool, AgentNetworkError>>,
    },
    CommonSnapshotVote {
        meta: PendingMeta,
        claim: Hash,
        reply: std_mpsc::Sender<Result<Option<ReplicaCommitSignature>, AgentNetworkError>>,
    },
    AppliedAvailability {
        meta: PendingMeta,
        request: AppliedAvailabilityRequest,
        reply: std_mpsc::Sender<Result<bool, AgentNetworkError>>,
    },
    CurrentAppliedAvailability {
        meta: PendingMeta,
        request: AppliedAvailabilityRequest,
        reply: std_mpsc::Sender<Result<bool, AgentNetworkError>>,
    },
    Invocation {
        meta: PendingMeta,
        request: InvocationRequest,
        reply: std_mpsc::Sender<Result<AgentInvocationResponse, AgentNetworkError>>,
    },
    RaftAppend {
        meta: PendingMeta,
        expected_match_index: u64,
        reply: oneshot::Sender<Result<AgentRaftAppendResponse, AgentNetworkError>>,
    },
    RaftVote {
        meta: PendingMeta,
        phase: RaftVotePhase,
        reply: oneshot::Sender<Result<AgentRaftVoteResponse, AgentNetworkError>>,
    },
    RaftInstallSnapshot {
        meta: PendingMeta,
        reply: oneshot::Sender<Result<AgentRaftInstallSnapshotResponse, AgentNetworkError>>,
    },
    RaftStatus {
        meta: PendingMeta,
        reply: oneshot::Sender<Result<Option<RaftStatus>, AgentNetworkError>>,
    },
    MergeHeads {
        meta: PendingMeta,
        reply: std_mpsc::Sender<Result<Vec<Hash>, AgentNetworkError>>,
    },
    MergeNode {
        meta: PendingMeta,
        hash: Hash,
        reply: std_mpsc::Sender<Result<Option<Vec<u8>>, AgentNetworkError>>,
    },
}

impl PendingAgentReply {
    fn meta(&self) -> PendingMeta {
        match self {
            Self::AuthorityReadBarrier { meta, .. }
            | Self::CommonSnapshotVote { meta, .. }
            | Self::ForwardedSharedInstall { meta, .. }
            | Self::ManagementRecoveryCommand { meta, .. }
            | Self::ManagementRecoveryOperation { meta, .. }
            | Self::AppliedAvailability { meta, .. }
            | Self::CurrentAppliedAvailability { meta, .. }
            | Self::Invocation { meta, .. }
            | Self::RaftAppend { meta, .. }
            | Self::RaftVote { meta, .. }
            | Self::RaftInstallSnapshot { meta, .. }
            | Self::RaftStatus { meta, .. }
            | Self::MergeHeads { meta, .. }
            | Self::MergeNode { meta, .. } => *meta,
        }
    }

    pub(super) fn fail(self, error: AgentNetworkError) {
        match self {
            Self::AuthorityReadBarrier { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::CommonSnapshotVote { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::AppliedAvailability { reply, .. }
            | Self::ManagementRecoveryCommand { reply, .. }
            | Self::ManagementRecoveryOperation { reply, .. }
            | Self::CurrentAppliedAvailability { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::ForwardedSharedInstall { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::Invocation { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::RaftAppend { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::RaftVote { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::RaftInstallSnapshot { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::RaftStatus { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::MergeHeads { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::MergeNode { reply, .. } => {
                let _ = reply.send(Err(error));
            }
        }
    }

    fn complete(self, peer: PeerId, authenticated: AuthenticatedAgentFrame) {
        let meta = self.meta();
        if peer != meta.target_peer {
            self.fail(AgentNetworkError::ResponsePeerMismatch);
            return;
        }
        if authenticated.sender() != meta.target_node {
            self.fail(AgentNetworkError::ResponseSenderMismatch);
            return;
        }
        if authenticated.frame().route != meta.route {
            self.fail(AgentNetworkError::ResponseRouteMismatch);
            return;
        }
        let message = authenticated.into_frame().message;
        match (self, message) {
            (
                Self::AuthorityReadBarrier { request, reply, .. },
                AgentMessage::AuthorityReadBarrierReply {
                    request: actual,
                    barrier,
                },
            ) => {
                let _ = reply.send(
                    if actual == request
                        && request != Hash::ZERO
                        && barrier.is_none_or(|barrier| {
                            barrier.is_valid()
                                && barrier.request == request
                                && barrier.leader == meta.target_node
                        })
                    {
                        Ok(barrier)
                    } else {
                        Err(AgentNetworkError::ResponseCorrelationMismatch)
                    },
                );
            }
            (
                Self::ForwardedSharedInstall {
                    request,
                    package_len,
                    reply,
                    ..
                },
                AgentMessage::ForwardedSharedInstallReply {
                    request: actual,
                    next_offset,
                },
            ) => {
                let _ = reply.send(if actual == request {
                    if next_offset.is_none_or(|offset| {
                        offset <= package_len
                            && (offset == package_len
                                || offset
                                    % crate::agent::shared_raft::ARTIFACT_CHUNK_DATA_BYTES as u64
                                    == 0)
                    }) {
                        Ok(next_offset)
                    } else {
                        Err(AgentNetworkError::ResponseCorrelationMismatch)
                    }
                } else {
                    Err(AgentNetworkError::ResponseCorrelationMismatch)
                });
            }
            (
                Self::ManagementRecoveryCommand { command, reply, .. },
                AgentMessage::ManagementRecoveryCommandReply {
                    command: actual,
                    applied,
                },
            ) => {
                let _ = reply.send(if actual == command {
                    Ok(applied)
                } else {
                    Err(AgentNetworkError::ResponseCorrelationMismatch)
                });
            }
            (
                Self::ManagementRecoveryOperation { request, reply, .. },
                AgentMessage::ManagementRecoveryOperationReply {
                    request: actual,
                    applied,
                },
            ) => {
                let _ = reply.send(if actual == request {
                    Ok(applied)
                } else {
                    Err(AgentNetworkError::ResponseCorrelationMismatch)
                });
            }
            (
                Self::CommonSnapshotVote { claim, reply, .. },
                AgentMessage::CommonSnapshotVoteReply {
                    claim: response,
                    signature,
                },
            ) => {
                let _ = reply.send(
                    if response == claim
                        && signature
                            .as_ref()
                            .is_none_or(|signature| signature.signer().0 == meta.target_node.0)
                    {
                        Ok(signature)
                    } else {
                        Err(AgentNetworkError::ResponseCorrelationMismatch)
                    },
                );
            }
            (
                Self::AppliedAvailability { request, reply, .. },
                AgentMessage::AppliedAvailabilityReply {
                    request: response,
                    available,
                },
            )
            | (
                Self::CurrentAppliedAvailability { request, reply, .. },
                AgentMessage::CurrentAppliedAvailabilityReply {
                    request: response,
                    available,
                },
            ) => {
                let _ = reply.send(if response == request {
                    Ok(available)
                } else {
                    Err(AgentNetworkError::ResponseCorrelationMismatch)
                });
            }
            (Self::Invocation { request, reply, .. }, AgentMessage::InvokeReply(response))
                if response.request == invocation_request_correlation(&request)
                    && outcome_matches_work(&response.outcome, &request.work) =>
            {
                let _ = reply.send(Ok(AgentInvocationResponse::Reply(response)));
            }
            (Self::Invocation { request, reply, .. }, AgentMessage::InvokeRedirect(response))
                if response.request == invocation_request_correlation(&request) =>
            {
                let _ = reply.send(Ok(AgentInvocationResponse::Redirect(response)));
            }
            (Self::Invocation { reply, .. }, AgentMessage::InvokeReply(_))
            | (Self::Invocation { reply, .. }, AgentMessage::InvokeRedirect(_)) => {
                let _ = reply.send(Err(AgentNetworkError::ResponseCorrelationMismatch));
            }
            (
                Self::RaftAppend {
                    expected_match_index,
                    reply,
                    ..
                },
                AgentMessage::Raft(RaftMessage::AppendReply {
                    term,
                    success,
                    match_index,
                }),
            ) if !success || match_index == expected_match_index => {
                let _ = reply.send(Ok(AgentRaftAppendResponse {
                    term,
                    success,
                    match_index,
                }));
            }
            (
                Self::RaftAppend { reply, .. },
                AgentMessage::Raft(RaftMessage::AppendReply { .. }),
            ) => {
                let _ = reply.send(Err(AgentNetworkError::ResponseCorrelationMismatch));
            }
            (
                Self::RaftVote { phase, reply, .. },
                AgentMessage::Raft(RaftMessage::VoteReply {
                    phase: response_phase,
                    term,
                    granted,
                }),
            ) if phase == response_phase => {
                let _ = reply.send(Ok(AgentRaftVoteResponse { term, granted }));
            }
            (Self::RaftVote { reply, .. }, AgentMessage::Raft(RaftMessage::VoteReply { .. })) => {
                let _ = reply.send(Err(AgentNetworkError::ResponseCorrelationMismatch));
            }
            (
                Self::RaftInstallSnapshot { reply, .. },
                AgentMessage::Raft(RaftMessage::InstallSnapshotReply {
                    term,
                    bytes_received,
                }),
            ) => {
                let _ = reply.send(Ok(AgentRaftInstallSnapshotResponse {
                    term,
                    bytes_received,
                }));
            }
            (
                Self::RaftStatus { reply, .. },
                AgentMessage::Raft(RaftMessage::StatusReply(status)),
            ) => {
                let _ = reply.send(Ok(status));
            }
            (Self::MergeHeads { reply, .. }, AgentMessage::Merge(MergeMessage::Heads(heads))) => {
                let _ = reply.send(Ok(heads));
            }
            (
                Self::MergeNode { hash, reply, .. },
                AgentMessage::Merge(MergeMessage::Node {
                    hash: response_hash,
                    bytes,
                }),
            ) if hash == response_hash => {
                let _ = reply.send(Ok(bytes));
            }
            (Self::MergeNode { reply, .. }, AgentMessage::Merge(MergeMessage::Node { .. })) => {
                let _ = reply.send(Err(AgentNetworkError::ResponseCorrelationMismatch));
            }
            (pending, _) => pending.fail(AgentNetworkError::ResponseTypeMismatch),
        }
    }
}

pub(super) struct AgentOutboundRequest {
    pub(super) peer: PeerId,
    pub(super) frame: AgentFrame,
    pub(super) pending: PendingAgentReply,
    permit: OwnedSemaphorePermit,
}

pub(super) struct TrackedAgentReply {
    pending: PendingAgentReply,
    _permit: OwnedSemaphorePermit,
}

impl TrackedAgentReply {
    fn fail(self, error: AgentNetworkError) {
        self.pending.fail(error);
    }

    fn complete(self, peer: PeerId, authenticated: AuthenticatedAgentFrame) {
        self.pending.complete(peer, authenticated);
    }
}

pub(super) type AgentOutboundReplies =
    HashMap<request_response::OutboundRequestId, TrackedAgentReply>;
pub(super) type AgentResponseChannel = (
    request_response::ResponseChannel<AgentFrame>,
    AgentFrame,
    tokio::sync::OwnedSemaphorePermit,
);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AgentTrafficClass {
    Application,
    Raft,
    Availability,
}

impl AgentTrafficClass {
    fn for_message(message: &AgentMessage) -> Self {
        match message {
            AgentMessage::Raft(_) => Self::Raft,
            AgentMessage::AppliedAvailabilityRequest(_)
            | AgentMessage::AppliedAvailabilityReply { .. }
            | AgentMessage::AuthorityReadBarrierRequest(_)
            | AgentMessage::AuthorityReadBarrierReply { .. }
            | AgentMessage::CurrentAppliedAvailabilityRequest(_)
            | AgentMessage::CurrentAppliedAvailabilityReply { .. }
            | AgentMessage::CommonSnapshotVoteRequest(_)
            | AgentMessage::CommonSnapshotVoteReply { .. } => Self::Availability,
            _ => Self::Application,
        }
    }
}

pub(super) struct AgentPermitPools {
    application: Arc<tokio::sync::Semaphore>,
    raft: Arc<tokio::sync::Semaphore>,
    // Availability checks must progress while application calls wait for
    // them, without competing for the reserved Raft control-plane capacity.
    availability: Arc<tokio::sync::Semaphore>,
}

impl AgentPermitPools {
    fn new(application: usize, raft: usize, availability: usize) -> Self {
        Self {
            application: Arc::new(tokio::sync::Semaphore::new(application)),
            raft: Arc::new(tokio::sync::Semaphore::new(raft)),
            availability: Arc::new(tokio::sync::Semaphore::new(availability)),
        }
    }

    fn try_acquire(
        &self,
        class: AgentTrafficClass,
    ) -> Result<OwnedSemaphorePermit, AgentNetworkError> {
        let permits = match class {
            AgentTrafficClass::Application => &self.application,
            AgentTrafficClass::Raft => &self.raft,
            AgentTrafficClass::Availability => &self.availability,
        };
        Arc::clone(permits)
            .try_acquire_owned()
            .map_err(|_| AgentNetworkError::OutboundCapacity)
    }

    #[cfg(test)]
    fn available(&self, class: AgentTrafficClass) -> usize {
        match class {
            AgentTrafficClass::Application => self.application.available_permits(),
            AgentTrafficClass::Raft => self.raft.available_permits(),
            AgentTrafficClass::Availability => self.availability.available_permits(),
        }
    }
}

pub(super) type AgentIngressPermits = AgentPermitPools;
pub(super) type AgentOutboundPermits = AgentPermitPools;

pub(super) fn new_agent_ingress_permits() -> AgentIngressPermits {
    AgentPermitPools::new(
        MAX_AGENT_INBOUND_APPLICATION_HANDLERS,
        MAX_AGENT_INBOUND_RAFT_HANDLERS,
        MAX_AGENT_INBOUND_AVAILABILITY_HANDLERS,
    )
}

pub(super) fn new_agent_outbound_permits() -> AgentOutboundPermits {
    AgentPermitPools::new(
        MAX_AGENT_OUTBOUND_APPLICATION_REQUESTS,
        MAX_AGENT_OUTBOUND_RAFT_REQUESTS,
        MAX_AGENT_OUTBOUND_AVAILABILITY_REQUESTS,
    )
}

fn reserve_agent_outbound_permit(
    permits: &AgentOutboundPermits,
    class: AgentTrafficClass,
) -> Result<OwnedSemaphorePermit, AgentNetworkError> {
    permits.try_acquire(class)
}

impl Network {
    /// Full clean identity of this network's Noise key.
    pub(crate) const fn agent_node_id(&self) -> NodeId {
        self.agent_node_id
    }

    /// Bind an admitted full Agent node to its exact Noise identity.  Both
    /// directions are immutable and bijective; duplicate exact bindings are
    /// idempotent while either-side conflicts fail closed.
    pub(crate) fn bind_agent_peer(
        &self,
        node: NodeId,
        peer: PeerId,
    ) -> Result<(), AgentNetworkError> {
        bind_peer(&self.agent_peers, node, peer)
    }

    /// Register one complete generation route and its canonical full-member
    /// set.  A route cannot be replaced in place.
    pub(crate) fn register_agent_route(
        &self,
        route: AgentGenerationRoute,
        members: Vec<NodeId>,
        handler: Arc<dyn AgentRouteHandler>,
    ) -> Result<(), AgentNetworkError> {
        if !route.is_valid() {
            return Err(AgentNetworkError::InvalidRoute);
        }
        if !valid_route_members(&members) || members.binary_search(&self.agent_node_id).is_err() {
            return Err(AgentNetworkError::InvalidMembership);
        }
        let Ok(mut routes) = self.agent_routes.lock() else {
            return Err(AgentNetworkError::Transport);
        };
        match routes.entry(route) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(Arc::new(AgentRouteRegistration { members, handler }));
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                Err(AgentNetworkError::RouteAlreadyRegistered)
            }
        }
    }

    /// Atomically install or refresh one live Shared-Agent generation and
    /// its exact Noise destinations. Existing registration is replaceable
    /// only by the identical handler owner; a competing owner fails closed.
    pub(crate) fn install_agent_route(
        &self,
        route: AgentGenerationRoute,
        mut members: Vec<(NodeId, PeerId)>,
        handler: Arc<dyn AgentRouteHandler>,
    ) -> Result<(), AgentNetworkError> {
        members.sort_unstable_by_key(|(node, _)| *node);
        let nodes = members.iter().map(|(node, _)| *node).collect::<Vec<_>>();
        if !route.is_valid()
            || !valid_route_members(&nodes)
            || nodes.binary_search(&self.agent_node_id).is_err()
            || members
                .iter()
                .any(|(node, peer)| *node != NodeId::of_authenticated_peer(&peer.to_bytes()))
        {
            return Err(AgentNetworkError::InvalidMembership);
        }
        let Ok(mut bindings) = self.agent_peers.lock() else {
            return Err(AgentNetworkError::Transport);
        };
        let Ok(mut routes) = self.agent_routes.lock() else {
            return Err(AgentNetworkError::Transport);
        };
        if let Some(existing) = routes.get(&route)
            && !Arc::ptr_eq(&existing.handler, &handler)
        {
            return Err(AgentNetworkError::RouteAlreadyRegistered);
        }
        for (node, peer) in &members {
            if bindings
                .by_node
                .get(node)
                .is_some_and(|existing| existing != peer)
            {
                return Err(AgentNetworkError::NodeAlreadyBound(*node));
            }
            if bindings
                .by_peer
                .get(peer)
                .is_some_and(|existing| existing != node)
            {
                return Err(AgentNetworkError::PeerAlreadyBound(*peer));
            }
        }

        let old_nodes = routes
            .get(&route)
            .map(|registration| registration.members.clone())
            .unwrap_or_default();
        for node in old_nodes {
            if nodes.binary_search(&node).is_err() {
                if let Some(owners) = bindings.owners.get_mut(&node) {
                    owners.remove(&route);
                    if owners.is_empty() {
                        bindings.owners.remove(&node);
                        if !bindings.pinned.contains(&node)
                            && let Some(peer) = bindings.by_node.remove(&node)
                        {
                            bindings.by_peer.remove(&peer);
                        }
                    }
                }
            }
        }
        for (node, peer) in members {
            bindings.by_node.entry(node).or_insert(peer);
            bindings.by_peer.entry(peer).or_insert(node);
            bindings.owners.entry(node).or_default().insert(route);
        }
        routes.insert(
            route,
            Arc::new(AgentRouteRegistration {
                members: nodes,
                handler,
            }),
        );
        Ok(())
    }

    /// Retire exactly one live generation owner and release only peer
    /// bindings no longer used or explicitly pinned by another API owner.
    pub(crate) fn retire_agent_route(
        &self,
        route: AgentGenerationRoute,
        handler: &Arc<dyn AgentRouteHandler>,
    ) -> bool {
        let Ok(mut bindings) = self.agent_peers.lock() else {
            return false;
        };
        let Ok(mut routes) = self.agent_routes.lock() else {
            return false;
        };
        let Some(registration) = routes.get(&route) else {
            return false;
        };
        if !Arc::ptr_eq(&registration.handler, handler) {
            return false;
        }
        let members = registration.members.clone();
        routes.remove(&route);
        for node in members {
            if let Some(owners) = bindings.owners.get_mut(&node) {
                owners.remove(&route);
                if owners.is_empty() {
                    bindings.owners.remove(&node);
                    if !bindings.pinned.contains(&node)
                        && let Some(peer) = bindings.by_node.remove(&node)
                    {
                        bindings.by_peer.remove(&peer);
                    }
                }
            }
        }
        true
    }

    /// Remove only the exact handler registration supplied by its owner.
    pub(crate) fn unregister_agent_route_if(
        &self,
        route: AgentGenerationRoute,
        handler: &Arc<dyn AgentRouteHandler>,
    ) -> bool {
        let Ok(mut routes) = self.agent_routes.lock() else {
            return false;
        };
        if routes
            .get(&route)
            .is_some_and(|entry| Arc::ptr_eq(&entry.handler, handler))
        {
            routes.remove(&route);
            true
        } else {
            false
        }
    }

    fn prepare_agent_request(
        &self,
        target: NodeId,
        route: AgentGenerationRoute,
        message: AgentMessage,
    ) -> Result<(PeerId, AgentFrame), AgentNetworkError> {
        let registration = self
            .agent_routes
            .lock()
            .ok()
            .and_then(|routes| routes.get(&route).cloned())
            .ok_or(AgentNetworkError::UnknownRoute(route))?;
        if !registration.contains(target) {
            return Err(AgentNetworkError::UnknownMember(target));
        }
        let peer = resolve_peer(&self.agent_peers, target)
            .ok_or(AgentNetworkError::UnknownDestination(target))?;
        let frame = AgentFrame {
            route,
            sender: self.agent_node_id,
            message,
        };
        frame.encode().map_err(AgentNetworkError::InvalidRequest)?;
        Ok((peer, frame))
    }

    fn queue_agent_request(&self, request: AgentOutboundRequest) {
        if let Err(error) = self.cmd_tx.send(NetworkCmd::SendAgent(Box::new(request))) {
            let NetworkCmd::SendAgent(request) = error.0 else {
                unreachable!("the failed command is the command that was sent")
            };
            request.pending.fail(AgentNetworkError::Disconnected);
        }
    }

    fn reserve_agent_outbound(
        &self,
        class: AgentTrafficClass,
    ) -> Result<OwnedSemaphorePermit, AgentNetworkError> {
        reserve_agent_outbound_permit(&self.agent_outbound_permits, class)
    }

    #[cfg(test)]
    pub(crate) fn authority_observation_available_permits_for_test(&self) -> usize {
        self.agent_outbound_permits
            .available(AgentTrafficClass::Availability)
    }

    /// Obtain bounded current-term freshness coordination from one exact
    /// admitted leader. The result is not a guest answer or transferable proof.
    /// The caller must apply and authenticate its own System state through R.
    pub(crate) fn send_agent_authority_read_barrier(
        &self,
        target: NodeId,
        route: AgentGenerationRoute,
        request: AuthorityReadBarrierRequest,
    ) -> std_mpsc::Receiver<Result<Option<AuthorityReadBarrier>, AgentNetworkError>> {
        let (reply, receiver) = std_mpsc::channel();
        let permit = match self.reserve_agent_outbound(AgentTrafficClass::Availability) {
            Ok(permit) => permit,
            Err(error) => {
                let _ = reply.send(Err(error));
                return receiver;
            }
        };
        match self.prepare_agent_request(
            target,
            route,
            AgentMessage::AuthorityReadBarrierRequest(request),
        ) {
            Ok((peer, frame)) => self.queue_agent_request(AgentOutboundRequest {
                peer,
                frame,
                permit,
                pending: PendingAgentReply::AuthorityReadBarrier {
                    meta: PendingMeta {
                        route,
                        target_node: target,
                        target_peer: peer,
                    },
                    request: request.request,
                    reply,
                },
            }),
            Err(error) => {
                let _ = reply.send(Err(error));
            }
        }
        receiver
    }

    /// Ask an exact authenticated replica about durable applied state. A
    /// positive reply is only one voter's evidence; callers own quorum policy.
    pub(crate) fn send_agent_applied_availability(
        &self,
        target: NodeId,
        route: AgentGenerationRoute,
        request: AppliedAvailabilityRequest,
    ) -> std_mpsc::Receiver<Result<bool, AgentNetworkError>> {
        let (reply, receiver) = std_mpsc::channel();
        let permit = match self.reserve_agent_outbound(AgentTrafficClass::Availability) {
            Ok(permit) => permit,
            Err(error) => {
                let _ = reply.send(Err(error));
                return receiver;
            }
        };
        match self.prepare_agent_request(
            target,
            route,
            AgentMessage::AppliedAvailabilityRequest(request),
        ) {
            Ok((peer, frame)) => self.queue_agent_request(AgentOutboundRequest {
                peer,
                frame,
                permit,
                pending: PendingAgentReply::AppliedAvailability {
                    meta: PendingMeta {
                        route,
                        target_node: target,
                        target_peer: peer,
                    },
                    request,
                    reply,
                },
            }),
            Err(error) => {
                let _ = reply.send(Err(error));
            }
        }
        receiver
    }

    /// Ask an exact authenticated voter about this current root only. A
    /// historical availability response cannot satisfy this request, and a
    /// positive reply remains one vote rather than a delivery certificate.
    pub(crate) fn send_agent_current_applied_availability(
        &self,
        target: NodeId,
        route: AgentGenerationRoute,
        request: AppliedAvailabilityRequest,
    ) -> std_mpsc::Receiver<Result<bool, AgentNetworkError>> {
        let (reply, receiver) = std_mpsc::channel();
        let permit = match self.reserve_agent_outbound(AgentTrafficClass::Availability) {
            Ok(permit) => permit,
            Err(error) => {
                let _ = reply.send(Err(error));
                return receiver;
            }
        };
        match self.prepare_agent_request(
            target,
            route,
            AgentMessage::CurrentAppliedAvailabilityRequest(request),
        ) {
            Ok((peer, frame)) => self.queue_agent_request(AgentOutboundRequest {
                peer,
                frame,
                permit,
                pending: PendingAgentReply::CurrentAppliedAvailability {
                    meta: PendingMeta {
                        route,
                        target_node: target,
                        target_peer: peer,
                    },
                    request,
                    reply,
                },
            }),
            Err(error) => {
                let _ = reply.send(Err(error));
            }
        }
        receiver
    }

    /// Request a typed vote over one exact common checkpoint. Authentication
    /// and correlation here do not replace independent signature verification
    /// by the certificate collector.
    pub(crate) fn send_agent_common_snapshot_vote(
        &self,
        target: NodeId,
        route: AgentGenerationRoute,
        claim: SharedAgentCommonSnapshotClaim,
    ) -> std_mpsc::Receiver<Result<Option<ReplicaCommitSignature>, AgentNetworkError>> {
        let (reply, receiver) = std_mpsc::channel();
        let permit = match self.reserve_agent_outbound(AgentTrafficClass::Availability) {
            Ok(permit) => permit,
            Err(error) => {
                let _ = reply.send(Err(error));
                return receiver;
            }
        };
        let commitment = Hash(claim.commitment().0);
        match self.prepare_agent_request(
            target,
            route,
            AgentMessage::CommonSnapshotVoteRequest(claim),
        ) {
            Ok((peer, frame)) => self.queue_agent_request(AgentOutboundRequest {
                peer,
                frame,
                permit,
                pending: PendingAgentReply::CommonSnapshotVote {
                    meta: PendingMeta {
                        route,
                        target_node: target,
                        target_peer: peer,
                    },
                    claim: commitment,
                    reply,
                },
            }),
            Err(error) => {
                let _ = reply.send(Err(error));
            }
        }
        receiver
    }

    /// Forward only the original owner's signed retention metadata. A true
    /// reply is not proof for cleanup: the owner must observe its local apply.
    pub(crate) fn send_agent_management_recovery_command(
        &self,
        target: NodeId,
        route: AgentGenerationRoute,
        command: AgentRaftCommand,
    ) -> std_mpsc::Receiver<Result<bool, AgentNetworkError>> {
        let (reply, receiver) = std_mpsc::channel();
        if !matches!(
            &command,
            AgentRaftCommand::RegisterManagementRecovery { .. }
                | AgentRaftCommand::ReleaseManagementRecovery { .. }
        ) {
            let _ = reply.send(Err(AgentNetworkError::InvalidRequestKind));
            return receiver;
        }
        let permit = match self.reserve_agent_outbound(AgentTrafficClass::Application) {
            Ok(permit) => permit,
            Err(error) => {
                let _ = reply.send(Err(error));
                return receiver;
            }
        };
        let commitment = Hash(command.commitment().0);
        match self.prepare_agent_request(
            target,
            route,
            AgentMessage::ManagementRecoveryCommandRequest(command),
        ) {
            Ok((peer, frame)) => self.queue_agent_request(AgentOutboundRequest {
                peer,
                frame,
                permit,
                pending: PendingAgentReply::ManagementRecoveryCommand {
                    meta: PendingMeta {
                        route,
                        target_node: target,
                        target_peer: peer,
                    },
                    command: commitment,
                    reply,
                },
            }),
            Err(error) => {
                let _ = reply.send(Err(error));
            }
        }
        receiver
    }

    /// Request one exact retained member operation, without carrying work,
    /// replay results, or permission for another owner to dispatch it offline.
    pub(crate) fn send_agent_management_recovery_operation(
        &self,
        target: NodeId,
        route: AgentGenerationRoute,
        request: ManagementRecoveryOperationRequest,
    ) -> std_mpsc::Receiver<Result<bool, AgentNetworkError>> {
        let (reply, receiver) = std_mpsc::channel();
        let permit = match self.reserve_agent_outbound(AgentTrafficClass::Application) {
            Ok(permit) => permit,
            Err(error) => {
                let _ = reply.send(Err(error));
                return receiver;
            }
        };
        let correlation = request.correlation();
        match self.prepare_agent_request(
            target,
            route,
            AgentMessage::ManagementRecoveryOperationRequest(request),
        ) {
            Ok((peer, frame)) => self.queue_agent_request(AgentOutboundRequest {
                peer,
                frame,
                permit,
                pending: PendingAgentReply::ManagementRecoveryOperation {
                    meta: PendingMeta {
                        route,
                        target_node: target,
                        target_peer: peer,
                    },
                    request: correlation,
                    reply,
                },
            }),
            Err(error) => {
                let _ = reply.send(Err(error));
            }
        }
        receiver
    }

    /// Transfer one bounded package chunk, or request its exact online-owner
    /// Install. The reply is only a scheduling/staging hint; the owner obtains
    /// management evidence from its own replayed journal before finalization.
    pub(crate) fn send_agent_forwarded_shared_install(
        &self,
        target: NodeId,
        route: AgentGenerationRoute,
        request: ForwardedSharedInstallRequest,
    ) -> std_mpsc::Receiver<Result<Option<u64>, AgentNetworkError>> {
        let (reply, receiver) = std_mpsc::channel();
        let permit = match self.reserve_agent_outbound(AgentTrafficClass::Application) {
            Ok(permit) => permit,
            Err(error) => {
                let _ = reply.send(Err(error));
                return receiver;
            }
        };
        let correlation = request.correlation();
        let package_len = match &request.request {
            crate::agent_sdk::ManagementRequest::Install(install) => install.package.len,
            _ => 0,
        };
        match self.prepare_agent_request(
            target,
            route,
            AgentMessage::ForwardedSharedInstallRequest(request),
        ) {
            Ok((peer, frame)) => self.queue_agent_request(AgentOutboundRequest {
                peer,
                frame,
                permit,
                pending: PendingAgentReply::ForwardedSharedInstall {
                    meta: PendingMeta {
                        route,
                        target_node: target,
                        target_peer: peer,
                    },
                    request: correlation,
                    package_len,
                    reply,
                },
            }),
            Err(error) => {
                let _ = reply.send(Err(error));
            }
        }
        receiver
    }

    pub(crate) fn send_agent_invocation(
        &self,
        target: NodeId,
        route: AgentGenerationRoute,
        request: InvocationRequest,
    ) -> std_mpsc::Receiver<Result<AgentInvocationResponse, AgentNetworkError>> {
        let (reply, receiver) = std_mpsc::channel();
        let permit = match self.reserve_agent_outbound(AgentTrafficClass::Application) {
            Ok(permit) => permit,
            Err(error) => {
                let _ = reply.send(Err(error));
                return receiver;
            }
        };
        match self.prepare_agent_request(
            target,
            route,
            AgentMessage::InvokeRequest(request.clone()),
        ) {
            Ok((peer, frame)) => self.queue_agent_request(AgentOutboundRequest {
                peer,
                frame,
                permit,
                pending: PendingAgentReply::Invocation {
                    meta: PendingMeta {
                        route,
                        target_node: target,
                        target_peer: peer,
                    },
                    request,
                    reply,
                },
            }),
            Err(error) => {
                let _ = reply.send(Err(error));
            }
        }
        receiver
    }

    pub(crate) fn send_agent_raft_append(
        &self,
        target: NodeId,
        route: AgentGenerationRoute,
        request: RaftMessage,
    ) -> oneshot::Receiver<Result<AgentRaftAppendResponse, AgentNetworkError>> {
        let (reply, receiver) = oneshot::channel();
        let RaftMessage::AppendRequest {
            prev_log_index,
            entries,
            ..
        } = &request
        else {
            let _ = reply.send(Err(AgentNetworkError::InvalidRequestKind));
            return receiver;
        };
        let expected_match_index = entries.last().map_or(*prev_log_index, |entry| entry.index);
        let permit = match self.reserve_agent_outbound(AgentTrafficClass::Raft) {
            Ok(permit) => permit,
            Err(error) => {
                let _ = reply.send(Err(error));
                return receiver;
            }
        };
        match self.prepare_agent_request(target, route, AgentMessage::Raft(request)) {
            Ok((peer, frame)) => self.queue_agent_request(AgentOutboundRequest {
                peer,
                frame,
                permit,
                pending: PendingAgentReply::RaftAppend {
                    meta: PendingMeta {
                        route,
                        target_node: target,
                        target_peer: peer,
                    },
                    expected_match_index,
                    reply,
                },
            }),
            Err(error) => {
                let _ = reply.send(Err(error));
            }
        }
        receiver
    }

    pub(crate) fn send_agent_raft_vote(
        &self,
        target: NodeId,
        route: AgentGenerationRoute,
        request: RaftMessage,
    ) -> oneshot::Receiver<Result<AgentRaftVoteResponse, AgentNetworkError>> {
        let (reply, receiver) = oneshot::channel();
        let RaftMessage::VoteRequest { phase, .. } = request else {
            let _ = reply.send(Err(AgentNetworkError::InvalidRequestKind));
            return receiver;
        };
        let permit = match self.reserve_agent_outbound(AgentTrafficClass::Raft) {
            Ok(permit) => permit,
            Err(error) => {
                let _ = reply.send(Err(error));
                return receiver;
            }
        };
        match self.prepare_agent_request(target, route, AgentMessage::Raft(request)) {
            Ok((peer, frame)) => self.queue_agent_request(AgentOutboundRequest {
                peer,
                frame,
                permit,
                pending: PendingAgentReply::RaftVote {
                    meta: PendingMeta {
                        route,
                        target_node: target,
                        target_peer: peer,
                    },
                    phase,
                    reply,
                },
            }),
            Err(error) => {
                let _ = reply.send(Err(error));
            }
        }
        receiver
    }

    pub(crate) fn send_agent_raft_install_snapshot(
        &self,
        target: NodeId,
        route: AgentGenerationRoute,
        request: RaftMessage,
    ) -> oneshot::Receiver<Result<AgentRaftInstallSnapshotResponse, AgentNetworkError>> {
        let (reply, receiver) = oneshot::channel();
        if !matches!(request, RaftMessage::InstallSnapshotRequest { .. }) {
            let _ = reply.send(Err(AgentNetworkError::InvalidRequestKind));
            return receiver;
        }
        let permit = match self.reserve_agent_outbound(AgentTrafficClass::Raft) {
            Ok(permit) => permit,
            Err(error) => {
                let _ = reply.send(Err(error));
                return receiver;
            }
        };
        match self.prepare_agent_request(target, route, AgentMessage::Raft(request)) {
            Ok((peer, frame)) => self.queue_agent_request(AgentOutboundRequest {
                peer,
                frame,
                permit,
                pending: PendingAgentReply::RaftInstallSnapshot {
                    meta: PendingMeta {
                        route,
                        target_node: target,
                        target_peer: peer,
                    },
                    reply,
                },
            }),
            Err(error) => {
                let _ = reply.send(Err(error));
            }
        }
        receiver
    }

    pub(crate) fn send_agent_raft_status(
        &self,
        target: NodeId,
        route: AgentGenerationRoute,
    ) -> oneshot::Receiver<Result<Option<RaftStatus>, AgentNetworkError>> {
        let (reply, receiver) = oneshot::channel();
        let permit = match self.reserve_agent_outbound(AgentTrafficClass::Raft) {
            Ok(permit) => permit,
            Err(error) => {
                let _ = reply.send(Err(error));
                return receiver;
            }
        };
        match self.prepare_agent_request(
            target,
            route,
            AgentMessage::Raft(RaftMessage::StatusRequest),
        ) {
            Ok((peer, frame)) => self.queue_agent_request(AgentOutboundRequest {
                peer,
                frame,
                permit,
                pending: PendingAgentReply::RaftStatus {
                    meta: PendingMeta {
                        route,
                        target_node: target,
                        target_peer: peer,
                    },
                    reply,
                },
            }),
            Err(error) => {
                let _ = reply.send(Err(error));
            }
        }
        receiver
    }

    pub(crate) fn send_agent_merge_fetch_heads(
        &self,
        target: NodeId,
        route: AgentGenerationRoute,
    ) -> std_mpsc::Receiver<Result<Vec<Hash>, AgentNetworkError>> {
        self.send_agent_merge_heads_request(target, route, MergeMessage::FetchHeads)
    }

    pub(crate) fn send_agent_merge_announce_heads(
        &self,
        target: NodeId,
        route: AgentGenerationRoute,
        heads: Vec<Hash>,
    ) -> std_mpsc::Receiver<Result<Vec<Hash>, AgentNetworkError>> {
        self.send_agent_merge_heads_request(target, route, MergeMessage::AnnounceHeads(heads))
    }

    fn send_agent_merge_heads_request(
        &self,
        target: NodeId,
        route: AgentGenerationRoute,
        request: MergeMessage,
    ) -> std_mpsc::Receiver<Result<Vec<Hash>, AgentNetworkError>> {
        let (reply, receiver) = std_mpsc::channel();
        let permit = match self.reserve_agent_outbound(AgentTrafficClass::Application) {
            Ok(permit) => permit,
            Err(error) => {
                let _ = reply.send(Err(error));
                return receiver;
            }
        };
        match self.prepare_agent_request(target, route, AgentMessage::Merge(request)) {
            Ok((peer, frame)) => self.queue_agent_request(AgentOutboundRequest {
                peer,
                frame,
                permit,
                pending: PendingAgentReply::MergeHeads {
                    meta: PendingMeta {
                        route,
                        target_node: target,
                        target_peer: peer,
                    },
                    reply,
                },
            }),
            Err(error) => {
                let _ = reply.send(Err(error));
            }
        }
        receiver
    }

    pub(crate) fn send_agent_merge_fetch_node(
        &self,
        target: NodeId,
        route: AgentGenerationRoute,
        hash: Hash,
    ) -> std_mpsc::Receiver<Result<Option<Vec<u8>>, AgentNetworkError>> {
        let (reply, receiver) = std_mpsc::channel();
        let permit = match self.reserve_agent_outbound(AgentTrafficClass::Application) {
            Ok(permit) => permit,
            Err(error) => {
                let _ = reply.send(Err(error));
                return receiver;
            }
        };
        match self.prepare_agent_request(
            target,
            route,
            AgentMessage::Merge(MergeMessage::FetchNode(hash)),
        ) {
            Ok((peer, frame)) => self.queue_agent_request(AgentOutboundRequest {
                peer,
                frame,
                permit,
                pending: PendingAgentReply::MergeNode {
                    meta: PendingMeta {
                        route,
                        target_node: target,
                        target_peer: peer,
                    },
                    hash,
                    reply,
                },
            }),
            Err(error) => {
                let _ = reply.send(Err(error));
            }
        }
        receiver
    }

    #[cfg(test)]
    pub(crate) fn send_agent_frame_for_test(&self, peer: PeerId, frame: AgentFrame) {
        let _ = self.cmd_tx.send(NetworkCmd::SendAgentUntracked {
            peer,
            frame: Box::new(frame),
        });
    }
}

fn authorize_inbound(
    peer: PeerId,
    frame: AgentFrame,
    routes: &AgentRouteDirectory,
) -> Result<(AuthenticatedAgentFrame, Arc<AgentRouteRegistration>), AgentNetworkError> {
    // Authentication is intentionally first.  Do not move route lookup above
    // this call: route existence and membership are state disclosures.
    let authenticated =
        authenticate_sender(&peer, frame).map_err(|_| AgentNetworkError::ResponseSenderMismatch)?;
    let route = authenticated.frame().route;
    let registration = routes
        .lock()
        .ok()
        .and_then(|routes| routes.get(&route).cloned())
        .ok_or(AgentNetworkError::UnknownRoute(route))?;
    if !registration.contains(authenticated.sender()) {
        return Err(AgentNetworkError::UnknownMember(authenticated.sender()));
    }
    Ok((authenticated, registration))
}

fn is_request(message: &AgentMessage) -> bool {
    matches!(
        message,
        AgentMessage::AuthorityReadBarrierRequest(_)
            | AgentMessage::InvokeRequest(_)
            | AgentMessage::ForwardedSharedInstallRequest(_)
            | AgentMessage::ManagementRecoveryCommandRequest(_)
            | AgentMessage::ManagementRecoveryOperationRequest(_)
            | AgentMessage::AppliedAvailabilityRequest(_)
            | AgentMessage::CurrentAppliedAvailabilityRequest(_)
            | AgentMessage::CommonSnapshotVoteRequest(_)
            | AgentMessage::Raft(RaftMessage::AppendRequest { .. })
            | AgentMessage::Raft(RaftMessage::VoteRequest { .. })
            | AgentMessage::Raft(RaftMessage::InstallSnapshotRequest { .. })
            | AgentMessage::Raft(RaftMessage::StatusRequest)
            | AgentMessage::Merge(MergeMessage::FetchHeads)
            | AgentMessage::Merge(MergeMessage::FetchNode(_))
            | AgentMessage::Merge(MergeMessage::AnnounceHeads(_))
    )
}

fn response_matches_request(request: &AgentMessage, response: &AgentMessage) -> bool {
    match (request, response) {
        (
            AgentMessage::AuthorityReadBarrierRequest(request),
            AgentMessage::AuthorityReadBarrierReply {
                request: actual,
                barrier,
            },
        ) => {
            request.request == *actual
                && request.request != Hash::ZERO
                && barrier
                    .is_none_or(|barrier| barrier.request == request.request && barrier.is_valid())
        }
        (
            AgentMessage::ForwardedSharedInstallRequest(request),
            AgentMessage::ForwardedSharedInstallReply {
                request: actual,
                next_offset,
            },
        ) => {
            request.correlation() == *actual
                && next_offset.is_none_or(|offset| request.admits_progress(offset))
        }
        (
            AgentMessage::ManagementRecoveryCommandRequest(command),
            AgentMessage::ManagementRecoveryCommandReply {
                command: actual, ..
            },
        ) => command.commitment().0 == actual.0,
        (
            AgentMessage::ManagementRecoveryOperationRequest(request),
            AgentMessage::ManagementRecoveryOperationReply {
                request: actual, ..
            },
        ) => request.correlation() == *actual,
        (
            AgentMessage::CommonSnapshotVoteRequest(request),
            AgentMessage::CommonSnapshotVoteReply { claim, .. },
        ) => request.commitment().0 == claim.0,
        (
            AgentMessage::AppliedAvailabilityRequest(request),
            AgentMessage::AppliedAvailabilityReply {
                request: response, ..
            },
        )
        | (
            AgentMessage::CurrentAppliedAvailabilityRequest(request),
            AgentMessage::CurrentAppliedAvailabilityReply {
                request: response, ..
            },
        ) => request == response,
        (AgentMessage::InvokeRequest(request), AgentMessage::InvokeReply(response)) => {
            response.request == invocation_request_correlation(request)
                && outcome_matches_work(&response.outcome, &request.work)
        }
        (AgentMessage::InvokeRequest(request), AgentMessage::InvokeRedirect(response)) => {
            response.request == invocation_request_correlation(request)
        }
        (
            AgentMessage::Raft(RaftMessage::AppendRequest { .. }),
            AgentMessage::Raft(RaftMessage::AppendReply { .. }),
        )
        | (
            AgentMessage::Raft(RaftMessage::InstallSnapshotRequest { .. }),
            AgentMessage::Raft(RaftMessage::InstallSnapshotReply { .. }),
        )
        | (
            AgentMessage::Raft(RaftMessage::StatusRequest),
            AgentMessage::Raft(RaftMessage::StatusReply(_)),
        )
        | (
            AgentMessage::Merge(MergeMessage::FetchHeads),
            AgentMessage::Merge(MergeMessage::Heads(_)),
        )
        | (
            AgentMessage::Merge(MergeMessage::AnnounceHeads(_)),
            AgentMessage::Merge(MergeMessage::Heads(_)),
        ) => true,
        (
            AgentMessage::Raft(RaftMessage::VoteRequest { phase, .. }),
            AgentMessage::Raft(RaftMessage::VoteReply {
                phase: response_phase,
                ..
            }),
        ) => phase == response_phase,
        (
            AgentMessage::Merge(MergeMessage::FetchNode(hash)),
            AgentMessage::Merge(MergeMessage::Node {
                hash: response_hash,
                ..
            }),
        ) => hash == response_hash,
        _ => false,
    }
}

fn outbound_failure(error: &request_response::OutboundFailure) -> AgentNetworkError {
    match error {
        request_response::OutboundFailure::Timeout => AgentNetworkError::Timeout,
        request_response::OutboundFailure::DialFailure
        | request_response::OutboundFailure::ConnectionClosed => AgentNetworkError::Disconnected,
        request_response::OutboundFailure::UnsupportedProtocols => {
            AgentNetworkError::UnsupportedProtocol
        }
        request_response::OutboundFailure::Io(_) => AgentNetworkError::Transport,
    }
}

pub(super) fn send_agent_request(
    swarm: &mut Swarm<VosBehaviour>,
    outbound: AgentOutboundRequest,
    pending: &mut AgentOutboundReplies,
) {
    let AgentOutboundRequest {
        peer,
        frame,
        pending: reply,
        permit,
    } = outbound;
    let request_id = swarm
        .behaviour_mut()
        .agent_req_resp
        .send_request(&peer, frame);
    pending.insert(
        request_id,
        TrackedAgentReply {
            pending: reply,
            _permit: permit,
        },
    );
}

pub(super) fn fail_all_agent_requests(
    pending: &mut AgentOutboundReplies,
    error: AgentNetworkError,
) {
    for (_, pending) in pending.drain() {
        pending.fail(error.clone());
    }
}

pub(super) fn handle_agent_event(
    event: request_response::Event<AgentFrame, AgentFrame>,
    local_node: NodeId,
    routes: &AgentRouteDirectory,
    pending: &mut AgentOutboundReplies,
    response_tx: &tokio::sync::mpsc::UnboundedSender<AgentResponseChannel>,
    ingress: &AgentIngressPermits,
) {
    match event {
        request_response::Event::Message { peer, message, .. } => match message {
            Message::Request {
                request, channel, ..
            } => {
                let Ok((authenticated, registration)) = authorize_inbound(peer, request, routes)
                else {
                    warn!(%peer, "network: rejected unauthenticated/unauthorized clean Agent request");
                    return;
                };
                if !is_request(&authenticated.frame().message) {
                    warn!(%peer, "network: clean Agent response arrived in request slot");
                    return;
                }
                let class = AgentTrafficClass::for_message(&authenticated.frame().message);
                let Ok(permit) = ingress.try_acquire(class) else {
                    debug!(%peer, "network: clean Agent inbound handler capacity exhausted");
                    return;
                };
                let request_message = authenticated.frame().message.clone();
                let route = authenticated.frame().route;
                let response_tx = response_tx.clone();
                let common_vote_admitted =
                    matches!(&request_message, AgentMessage::CommonSnapshotVoteRequest(_))
                        .then(std::time::Instant::now);
                tokio::task::spawn_blocking(move || {
                    if let Some(admitted) = common_vote_admitted {
                        debug!(
                            node = ?local_node,
                            ?route,
                            phase = "handler_started",
                            elapsed_us = admitted.elapsed().as_micros(),
                            "Common checkpoint vote dispatch phase"
                        );
                    }
                    let Ok(response_message) = registration.handler.handle(authenticated) else {
                        return;
                    };
                    if !response_matches_request(&request_message, &response_message) {
                        warn!(%peer, "network: clean Agent handler returned a mismatched response");
                        return;
                    }
                    let response = AgentFrame {
                        route,
                        sender: local_node,
                        message: response_message,
                    };
                    if response.encode().is_err() {
                        warn!(%peer, "network: clean Agent handler returned an invalid response");
                        return;
                    }
                    // Move the permit with the response so both handler jobs
                    // and not-yet-drained response channels share one cap.
                    let _ = response_tx.send((channel, response, permit));
                    if let Some(admitted) = common_vote_admitted {
                        debug!(
                            node = ?local_node,
                            ?route,
                            phase = "handler_completed",
                            elapsed_us = admitted.elapsed().as_micros(),
                            "Common checkpoint vote dispatch phase"
                        );
                    }
                });
            }
            Message::Response {
                response,
                request_id,
            } => {
                // Authenticate before route/member lookup or pending-response
                // inspection.  A failed authentication still removes the
                // opaque request-id slot to avoid retaining attacker-triggered
                // bookkeeping indefinitely.
                let authenticated = match authenticate_sender(&peer, response) {
                    Ok(authenticated) => authenticated,
                    Err(_) => {
                        if let Some(pending) = pending.remove(&request_id) {
                            pending.fail(AgentNetworkError::ResponseSenderMismatch);
                        }
                        return;
                    }
                };
                let route = authenticated.frame().route;
                let registration = routes
                    .lock()
                    .ok()
                    .and_then(|routes| routes.get(&route).cloned());
                let Some(registration) = registration else {
                    if let Some(pending) = pending.remove(&request_id) {
                        pending.fail(AgentNetworkError::UnknownRoute(route));
                    }
                    return;
                };
                if !registration.contains(authenticated.sender()) {
                    if let Some(pending) = pending.remove(&request_id) {
                        pending.fail(AgentNetworkError::UnknownMember(authenticated.sender()));
                    }
                    return;
                }
                match pending.remove(&request_id) {
                    Some(pending) => pending.complete(peer, authenticated),
                    None => warn!(%peer, "network: unsolicited clean Agent response"),
                }
            }
        },
        request_response::Event::OutboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            debug!(%peer, %error, "network: clean Agent outbound request failed");
            if let Some(pending) = pending.remove(&request_id) {
                pending.fail(outbound_failure(&error));
            }
        }
        request_response::Event::InboundFailure { peer, error, .. } => {
            debug!(%peer, %error, "network: clean Agent inbound request failed");
        }
        request_response::Event::ResponseSent { .. } => {}
    }
}

#[cfg(test)]
mod tests {
    use libp2p::Multiaddr;
    use libp2p::identity;
    use vos_agent_sdk::authority::{
        AuthorityEvidence, AuthorityIssuer, AuthorityLaneRoots, AuthorityOperationKind,
        AuthorityReceipt, AuthorityReceiptSelector,
    };
    use vos_agent_sdk::{
        ActorId, AgentId, DeploymentId, InvocationAuthorization, InvocationId, InvocationOrigin,
        InvocationRoleClaims, MethodMode, PrincipalId, ProducerId, ProgramId, PublicPreflight,
        RuntimeOutcome, SpaceId,
    };

    use super::*;
    use crate::network::{NetworkConfig, derive_node_prefix};

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn test_route(byte: u8) -> AgentGenerationRoute {
        AgentGenerationRoute {
            space: SpaceId(id(byte)),
            agent: AgentId(id(byte.wrapping_add(1))),
            generation: Hash(id(byte.wrapping_add(2))),
        }
    }

    fn key(seed: u8) -> identity::Keypair {
        identity::Keypair::ed25519_from_bytes([seed; 32]).expect("deterministic Ed25519 key")
    }

    fn node(peer: PeerId) -> NodeId {
        NodeId::of_authenticated_peer(&peer.to_bytes())
    }

    fn frame(peer: PeerId, route: AgentGenerationRoute, message: AgentMessage) -> AgentFrame {
        AgentFrame {
            route,
            sender: node(peer),
            message,
        }
    }

    struct StaticHandler {
        calls: Arc<Mutex<Vec<NodeId>>>,
        response: Option<AgentMessage>,
        delay: Option<Duration>,
    }

    impl AgentRouteHandler for StaticHandler {
        fn handle(
            &self,
            request: AuthenticatedAgentFrame,
        ) -> Result<AgentMessage, AgentHandlerError> {
            self.calls.lock().unwrap().push(request.sender());
            if let Some(delay) = self.delay {
                std::thread::sleep(delay);
            }
            self.response.clone().ok_or(AgentHandlerError)
        }
    }

    fn registration(
        members: Vec<NodeId>,
        calls: Arc<Mutex<Vec<NodeId>>>,
    ) -> Arc<AgentRouteRegistration> {
        Arc::new(AgentRouteRegistration {
            members,
            handler: Arc::new(StaticHandler {
                calls,
                response: Some(AgentMessage::Merge(MergeMessage::Heads(vec![Hash(id(90))]))),
                delay: None,
            }),
        })
    }

    #[test]
    fn exact_peer_directory_preserves_compact_collisions_and_is_bijective() {
        let mut by_prefix = BTreeMap::new();
        let (first, second, prefix) = (1u64..=8_192)
            .find_map(|counter| {
                let mut seed = [0; 32];
                seed[..8].copy_from_slice(&counter.to_le_bytes());
                seed[8..16].copy_from_slice(&counter.rotate_left(17).to_le_bytes());
                seed[16..24].copy_from_slice(&counter.rotate_left(31).to_le_bytes());
                seed[24..].copy_from_slice(&counter.rotate_left(47).to_le_bytes());
                let peer = identity::Keypair::ed25519_from_bytes(seed)
                    .unwrap()
                    .public()
                    .to_peer_id();
                let prefix = derive_node_prefix(&peer);
                by_prefix
                    .insert(prefix, peer)
                    .map(|previous| (previous, peer, prefix))
            })
            .expect("deterministic fixture contains a compact collision");
        assert_ne!(first, second);
        assert_eq!(derive_node_prefix(&first), prefix);
        assert_eq!(derive_node_prefix(&second), prefix);

        let directory = new_agent_peer_directory(key(200).public().to_peer_id());
        bind_peer(&directory, node(first), first).unwrap();
        bind_peer(&directory, node(second), second).unwrap();
        assert_eq!(resolve_peer(&directory, node(first)), Some(first));
        assert_eq!(resolve_peer(&directory, node(second)), Some(second));
        assert_ne!(node(first), node(second));

        let wrong_claim = NodeId(id(44));
        assert!(matches!(
            bind_peer(&directory, wrong_claim, first),
            Err(AgentNetworkError::NodeIdentityMismatch { .. })
        ));
    }

    #[test]
    fn route_directory_admits_two_full_committees_but_not_an_unbounded_union() {
        let mut members = (1..=MAX_AGENT_ROUTE_MEMBERS)
            .map(|index| {
                let mut bytes = [0_u8; 32];
                bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
                NodeId(bytes)
            })
            .collect::<Vec<_>>();
        assert!(valid_route_members(&members));
        let mut extra = [0xff; 32];
        extra[..8].copy_from_slice(&((MAX_AGENT_ROUTE_MEMBERS + 1) as u64).to_be_bytes());
        members.push(NodeId(extra));
        members.sort_unstable();
        assert!(!valid_route_members(&members));
    }

    #[test]
    fn sender_authentication_precedes_route_and_membership_access() {
        let honest = key(1).public().to_peer_id();
        let attacker = key(2).public().to_peer_id();
        let route = test_route(10);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let routes = Arc::new(Mutex::new(BTreeMap::from([(
            route,
            registration(vec![node(honest)], calls.clone()),
        )])));

        let forged = AgentFrame {
            route,
            sender: node(honest),
            message: AgentMessage::Merge(MergeMessage::FetchHeads),
        };
        assert_eq!(
            authorize_inbound(attacker, forged, &routes).err().unwrap(),
            AgentNetworkError::ResponseSenderMismatch
        );
        assert!(calls.lock().unwrap().is_empty());

        let unknown_route = frame(
            honest,
            test_route(30),
            AgentMessage::Merge(MergeMessage::FetchHeads),
        );
        assert!(matches!(
            authorize_inbound(honest, unknown_route, &routes),
            Err(AgentNetworkError::UnknownRoute(_))
        ));

        let nonmember = frame(
            attacker,
            route,
            AgentMessage::Merge(MergeMessage::FetchHeads),
        );
        assert_eq!(
            authorize_inbound(attacker, nonmember, &routes)
                .err()
                .unwrap(),
            AgentNetworkError::UnknownMember(node(attacker))
        );
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn forwarded_shared_install_replies_require_exact_peer_sender_route_kind_and_commitment() {
        let peer = key(91).public().to_peer_id();
        let other = key(92).public().to_peer_id();
        let route = test_route(91);
        let correlation = Hash(id(93));
        for fault in 0..9 {
            let (reply, result) = std_mpsc::channel();
            let pending = PendingAgentReply::ForwardedSharedInstall {
                meta: PendingMeta {
                    route,
                    target_node: node(peer),
                    target_peer: peer,
                },
                request: correlation,
                package_len: 100,
                reply,
            };
            let mut response = frame(
                peer,
                route,
                AgentMessage::ForwardedSharedInstallReply {
                    request: if fault == 2 {
                        Hash(id(94))
                    } else {
                        correlation
                    },
                    next_offset: match fault {
                        1 => None,
                        7 => Some(101),
                        8 => Some(1),
                        _ => Some(100),
                    },
                },
            );
            if fault == 3 {
                response.route.generation = Hash(id(95));
            }
            if fault == 5 {
                response.sender = node(other);
            }
            if fault == 6 {
                response.message = AgentMessage::ManagementRecoveryOperationReply {
                    request: correlation,
                    applied: true,
                };
            }
            let authenticated =
                authenticate_sender(if fault == 5 { &other } else { &peer }, response).unwrap();
            pending.complete(if fault == 4 { other } else { peer }, authenticated);
            let expected = match fault {
                0 => Ok(Some(100)),
                1 => Ok(None),
                2 => Err(AgentNetworkError::ResponseCorrelationMismatch),
                3 => Err(AgentNetworkError::ResponseRouteMismatch),
                4 => Err(AgentNetworkError::ResponsePeerMismatch),
                5 => Err(AgentNetworkError::ResponseSenderMismatch),
                6 => Err(AgentNetworkError::ResponseTypeMismatch),
                _ => Err(AgentNetworkError::ResponseCorrelationMismatch),
            };
            assert_eq!(result.recv().unwrap(), expected);
        }
    }

    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    #[test]
    fn forwarded_shared_install_uses_existing_application_pool_and_exact_chunk_correlations() {
        let (route, request) =
            super::super::agent_protocol::forwarded_shared_install_for_test(true);
        let chunk = AgentMessage::ForwardedSharedInstallRequest(request.clone());
        assert!(is_request(&chunk));
        assert!(matches!(
            AgentTrafficClass::for_message(&chunk),
            AgentTrafficClass::Application
        ));
        let reply = AgentMessage::ForwardedSharedInstallReply {
            request: request.correlation(),
            next_offset: Some(0),
        };
        assert!(response_matches_request(&chunk, &reply));
        let finish = AgentMessage::ForwardedSharedInstallRequest(ForwardedSharedInstallRequest {
            operation: super::super::agent_protocol::ForwardedSharedInstallOperation::Finish,
            ..request
        });
        assert!(!response_matches_request(&finish, &reply));
        assert!(!response_matches_request(
            &chunk,
            &AgentMessage::ManagementRecoveryOperationReply {
                request: Hash(id(93)),
                applied: true,
            }
        ));
        let pools = new_agent_outbound_permits();
        let permits = (0..MAX_AGENT_OUTBOUND_APPLICATION_REQUESTS)
            .map(|_| pools.try_acquire(AgentTrafficClass::Application).unwrap())
            .collect::<Vec<_>>();
        assert!(pools.try_acquire(AgentTrafficClass::Application).is_err());
        assert!(pools.try_acquire(AgentTrafficClass::Raft).is_ok());
        assert!(pools.try_acquire(AgentTrafficClass::Availability).is_ok());
        drop(permits);
        assert!(route.is_valid());
    }

    #[test]
    fn management_recovery_replies_require_exact_peer_sender_route_kind_and_commitment() {
        let peer = key(84).public().to_peer_id();
        let other = key(85).public().to_peer_id();
        let route = test_route(84);
        let correlation = Hash(id(86));
        for operation in [false, true] {
            for fault in 0..7 {
                let (reply, result) = std_mpsc::channel();
                let meta = PendingMeta {
                    route,
                    target_node: node(peer),
                    target_peer: peer,
                };
                let pending = if operation {
                    PendingAgentReply::ManagementRecoveryOperation {
                        meta,
                        request: correlation,
                        reply,
                    }
                } else {
                    PendingAgentReply::ManagementRecoveryCommand {
                        meta,
                        command: correlation,
                        reply,
                    }
                };
                let actual = if fault == 2 {
                    Hash(id(87))
                } else {
                    correlation
                };
                let mut response = frame(
                    peer,
                    route,
                    if operation {
                        AgentMessage::ManagementRecoveryOperationReply {
                            request: actual,
                            applied: fault != 1,
                        }
                    } else {
                        AgentMessage::ManagementRecoveryCommandReply {
                            command: actual,
                            applied: fault != 1,
                        }
                    },
                );
                if fault == 3 {
                    response.route.generation = Hash(id(88));
                }
                if fault == 5 {
                    response.sender = node(other);
                }
                if fault == 6 {
                    response.message = if operation {
                        AgentMessage::ManagementRecoveryCommandReply {
                            command: actual,
                            applied: true,
                        }
                    } else {
                        AgentMessage::ManagementRecoveryOperationReply {
                            request: actual,
                            applied: true,
                        }
                    };
                }
                let authenticated =
                    authenticate_sender(if fault == 5 { &other } else { &peer }, response).unwrap();
                pending.complete(if fault == 4 { other } else { peer }, authenticated);
                let expected = match fault {
                    0 => Ok(true),
                    1 => Ok(false),
                    2 => Err(AgentNetworkError::ResponseCorrelationMismatch),
                    3 => Err(AgentNetworkError::ResponseRouteMismatch),
                    4 => Err(AgentNetworkError::ResponsePeerMismatch),
                    5 => Err(AgentNetworkError::ResponseSenderMismatch),
                    6 => Err(AgentNetworkError::ResponseTypeMismatch),
                    _ => unreachable!(),
                };
                assert_eq!(
                    result.recv().unwrap(),
                    expected,
                    "operation={operation} fault={fault}"
                );
            }
        }
    }

    #[test]
    fn management_recovery_uses_bounded_application_pool_and_distinct_exact_replies() {
        let mut messages = Vec::new();
        for command in super::super::agent_protocol::management_recovery_commands_for_test() {
            let request = AgentMessage::ManagementRecoveryCommandRequest(command.clone());
            let reply = AgentMessage::ManagementRecoveryCommandReply {
                command: Hash(command.commitment().0),
                applied: true,
            };
            assert!(is_request(&request));
            assert!(!is_request(&reply));
            assert!(response_matches_request(&request, &reply));
            assert!(!response_matches_request(
                &request,
                &AgentMessage::ManagementRecoveryCommandReply {
                    command: Hash(id(99)),
                    applied: true
                }
            ));
            messages.extend([request, reply]);
        }
        let invoke = ManagementRecoveryOperationRequest {
            registration: Hash(id(90)),
            member: Hash(id(91)),
            operation: super::super::agent_protocol::ManagementRecoveryOperation::Invoke,
        };
        let acknowledge = ManagementRecoveryOperationRequest {
            operation: super::super::agent_protocol::ManagementRecoveryOperation::Acknowledge,
            ..invoke
        };
        for request in [invoke, acknowledge] {
            let message = AgentMessage::ManagementRecoveryOperationRequest(request);
            let reply = AgentMessage::ManagementRecoveryOperationReply {
                request: request.correlation(),
                applied: true,
            };
            assert!(is_request(&message));
            assert!(!is_request(&reply));
            assert!(response_matches_request(&message, &reply));
            assert!(!response_matches_request(
                &message,
                &AgentMessage::ManagementRecoveryOperationReply {
                    request: Hash(id(99)),
                    applied: true
                }
            ));
            messages.extend([message, reply]);
        }
        assert!(!response_matches_request(
            &AgentMessage::ManagementRecoveryOperationRequest(invoke),
            &AgentMessage::ManagementRecoveryOperationReply {
                request: acknowledge.correlation(),
                applied: true
            },
        ));
        for message in &messages {
            assert_eq!(
                AgentTrafficClass::for_message(message),
                AgentTrafficClass::Application
            );
        }
        let pools = new_agent_outbound_permits();
        let _application = pools
            .application
            .clone()
            .try_acquire_many_owned(MAX_AGENT_OUTBOUND_APPLICATION_REQUESTS as u32)
            .unwrap();
        assert!(reserve_agent_outbound_permit(&pools, AgentTrafficClass::Application).is_err());
        assert_eq!(
            pools.available(AgentTrafficClass::Raft),
            MAX_AGENT_OUTBOUND_RAFT_REQUESTS
        );
        assert_eq!(
            pools.available(AgentTrafficClass::Availability),
            MAX_AGENT_OUTBOUND_AVAILABILITY_REQUESTS
        );
    }

    #[test]
    fn snapshot_votes_require_exact_peer_sender_route_claim_and_signer() {
        let peer = key(84).public().to_peer_id();
        let other = key(85).public().to_peer_id();
        let route = test_route(84);
        let claim = Hash(id(86));
        let signature =
            ReplicaCommitSignature::new(crate::service::NodeId(node(peer).0), [7; 64]).unwrap();
        for fault in 0..8 {
            let (reply, result) = std_mpsc::channel();
            let meta = PendingMeta {
                route,
                target_node: node(peer),
                target_peer: peer,
            };
            let pending = PendingAgentReply::CommonSnapshotVote { meta, claim, reply };
            let response_hash = if fault == 2 { Hash(id(87)) } else { claim };
            let response_signature = if fault == 1 {
                None
            } else if fault == 3 {
                Some(
                    ReplicaCommitSignature::new(crate::service::NodeId(node(other).0), [7; 64])
                        .unwrap(),
                )
            } else {
                Some(signature.clone())
            };
            let mut response = frame(
                peer,
                route,
                AgentMessage::CommonSnapshotVoteReply {
                    claim: response_hash,
                    signature: response_signature,
                },
            );
            if fault == 4 {
                response.route.generation = Hash(id(88));
            }
            if fault == 6 {
                response.sender = node(other);
            }
            if fault == 7 {
                response.message = AgentMessage::ManagementRecoveryCommandReply {
                    command: claim,
                    applied: true,
                };
            }
            let authenticated =
                authenticate_sender(if fault == 6 { &other } else { &peer }, response).unwrap();
            pending.complete(if fault == 5 { other } else { peer }, authenticated);
            let expected = match fault {
                0 => Ok(Some(signature.clone())),
                1 => Ok(None),
                2 | 3 => Err(AgentNetworkError::ResponseCorrelationMismatch),
                4 => Err(AgentNetworkError::ResponseRouteMismatch),
                5 => Err(AgentNetworkError::ResponsePeerMismatch),
                6 => Err(AgentNetworkError::ResponseSenderMismatch),
                7 => Err(AgentNetworkError::ResponseTypeMismatch),
                _ => unreachable!(),
            };
            assert_eq!(result.recv().unwrap(), expected, "fault {fault}");
        }
    }

    #[test]
    fn common_snapshot_votes_use_existing_bounded_availability_pool() {
        let claim = crate::agent::shared_commit::common_snapshot_claim_for_test();
        let request = AgentMessage::CommonSnapshotVoteRequest(claim.clone());
        let reply = AgentMessage::CommonSnapshotVoteReply {
            claim: Hash(claim.commitment().0),
            signature: None,
        };
        assert!(is_request(&request));
        assert!(!is_request(&reply));
        assert!(response_matches_request(&request, &reply));
        for message in [&request, &reply] {
            assert_eq!(
                AgentTrafficClass::for_message(message),
                AgentTrafficClass::Availability
            );
        }
        assert!(!response_matches_request(
            &request,
            &AgentMessage::CommonSnapshotVoteReply {
                claim: Hash(id(99)),
                signature: None,
            }
        ));
        let pools = new_agent_outbound_permits();
        let _application = pools
            .application
            .clone()
            .try_acquire_many_owned(MAX_AGENT_OUTBOUND_APPLICATION_REQUESTS as u32)
            .unwrap();
        let vote = reserve_agent_outbound_permit(&pools, AgentTrafficClass::Availability).unwrap();
        assert_eq!(
            pools.available(AgentTrafficClass::Availability),
            MAX_AGENT_OUTBOUND_AVAILABILITY_REQUESTS - 1
        );
        assert_eq!(
            pools.available(AgentTrafficClass::Raft),
            MAX_AGENT_OUTBOUND_RAFT_REQUESTS
        );
        drop(vote);
        assert_eq!(
            pools.available(AgentTrafficClass::Availability),
            MAX_AGENT_OUTBOUND_AVAILABILITY_REQUESTS
        );
    }

    #[test]
    fn applied_availability_requires_exact_peer_sender_route_and_full_claim() {
        let peer = key(86).public().to_peer_id();
        let other_peer = key(87).public().to_peer_id();
        let route = test_route(86);
        let request = AppliedAvailabilityRequest {
            raft_index: 7,
            raft_term: 3,
            claim: Hash(id(88)),
        };
        for fault in 0..11 {
            let (reply, result) = std_mpsc::channel();
            let pending = PendingAgentReply::AppliedAvailability {
                meta: PendingMeta {
                    route,
                    target_node: node(peer),
                    target_peer: peer,
                },
                request,
                reply,
            };
            let mut echoed = request;
            match fault {
                2 => echoed.raft_index += 1,
                3 => echoed.raft_term += 1,
                4 => echoed.claim = Hash(id(89)),
                _ => {}
            }
            let mut response = frame(
                peer,
                route,
                AgentMessage::AppliedAvailabilityReply {
                    request: echoed,
                    available: fault != 1,
                },
            );
            match fault {
                5 => response.route.space = SpaceId(id(90)),
                6 => response.route.agent = AgentId(id(90)),
                7 => response.route.generation = Hash(id(90)),
                9 => response.sender = node(other_peer),
                10 => {
                    response.message = AgentMessage::Raft(RaftMessage::AppendReply {
                        term: request.raft_term,
                        success: true,
                        match_index: request.raft_index,
                    })
                }
                _ => {}
            }
            let authenticated =
                authenticate_sender(if fault == 9 { &other_peer } else { &peer }, response)
                    .unwrap();
            pending.complete(if fault == 8 { other_peer } else { peer }, authenticated);
            let expected = match fault {
                0 => Ok(true),
                1 => Ok(false),
                2..=4 => Err(AgentNetworkError::ResponseCorrelationMismatch),
                5..=7 => Err(AgentNetworkError::ResponseRouteMismatch),
                8 => Err(AgentNetworkError::ResponsePeerMismatch),
                9 => Err(AgentNetworkError::ResponseSenderMismatch),
                10 => Err(AgentNetworkError::ResponseTypeMismatch),
                _ => unreachable!(),
            };
            assert_eq!(result.recv().unwrap(), expected, "fault {fault}");
        }
    }

    #[test]
    fn applied_availability_is_non_execution_traffic_with_exact_response_matching() {
        let claim = AppliedAvailabilityRequest {
            raft_index: 9,
            raft_term: 2,
            claim: Hash(id(91)),
        };
        let request = AgentMessage::AppliedAvailabilityRequest(claim);
        assert!(is_request(&request));
        assert_eq!(
            AgentTrafficClass::for_message(&request),
            AgentTrafficClass::Availability
        );
        for available in [false, true] {
            let reply = AgentMessage::AppliedAvailabilityReply {
                request: claim,
                available,
            };
            assert!(!is_request(&reply));
            assert_eq!(
                AgentTrafficClass::for_message(&reply),
                AgentTrafficClass::Availability
            );
            assert!(response_matches_request(&request, &reply));
        }
        for wrong in [
            AppliedAvailabilityRequest {
                raft_index: 10,
                ..claim
            },
            AppliedAvailabilityRequest {
                raft_term: 3,
                ..claim
            },
            AppliedAvailabilityRequest {
                claim: Hash(id(92)),
                ..claim
            },
        ] {
            assert!(!response_matches_request(
                &request,
                &AgentMessage::AppliedAvailabilityReply {
                    request: wrong,
                    available: true
                },
            ));
        }
        assert!(!response_matches_request(&request, &request));
        let append = AgentMessage::Raft(RaftMessage::AppendReply {
            term: claim.raft_term,
            success: true,
            match_index: claim.raft_index,
        });
        assert!(!response_matches_request(&request, &append));
        assert_eq!(
            AgentTrafficClass::for_message(&append),
            AgentTrafficClass::Raft
        );
        let invoke = AgentMessage::InvokeRequest(invocation_request(
            test_route(91),
            ActorId(id(92)),
            InvocationId(id(93)),
        ));
        assert_eq!(
            AgentTrafficClass::for_message(&invoke),
            AgentTrafficClass::Application
        );
    }

    #[test]
    fn authority_read_barrier_requires_exact_request_peer_route_and_kind() {
        let peer = key(86).public().to_peer_id();
        let other_peer = key(87).public().to_peer_id();
        let route = test_route(86);
        let request = Hash(id(88));
        let barrier = AuthorityReadBarrier {
            request,
            leader: node(peer),
            raft_term: 3,
            read_index: 7,
            configuration_index: 0,
        };
        for fault in 0..15 {
            let (reply, result) = std_mpsc::channel();
            let pending = PendingAgentReply::AuthorityReadBarrier {
                meta: PendingMeta {
                    route,
                    target_node: node(peer),
                    target_peer: peer,
                },
                request,
                reply,
            };
            let mut altered = barrier;
            match fault {
                3 => altered.request = Hash(id(89)),
                4 => altered.leader = node(other_peer),
                5 => altered.raft_term = 0,
                6 => altered.read_index = 0,
                7 => altered.configuration_index = 8,
                _ => {}
            }
            let mut response = frame(
                peer,
                route,
                AgentMessage::AuthorityReadBarrierReply {
                    request: if fault == 2 { Hash(id(89)) } else { request },
                    barrier: (fault != 1).then_some(altered),
                },
            );
            match fault {
                8 => response.route.space = SpaceId(id(90)),
                9 => response.route.agent = AgentId(id(90)),
                10 => response.route.generation = Hash(id(90)),
                12 => response.sender = node(other_peer),
                13 => response.message = AgentMessage::Raft(RaftMessage::StatusReply(None)),
                14 => {
                    response.message = AgentMessage::ManagementRecoveryCommandReply {
                        command: request,
                        applied: true,
                    }
                }
                _ => {}
            }
            let authenticated =
                authenticate_sender(if fault == 12 { &other_peer } else { &peer }, response)
                    .unwrap();
            pending.complete(if fault == 11 { other_peer } else { peer }, authenticated);
            let expected = match fault {
                0 => Ok(Some(barrier)),
                1 => Ok(None),
                2..=7 => Err(AgentNetworkError::ResponseCorrelationMismatch),
                8..=10 => Err(AgentNetworkError::ResponseRouteMismatch),
                11 => Err(AgentNetworkError::ResponsePeerMismatch),
                12 => Err(AgentNetworkError::ResponseSenderMismatch),
                13..=14 => Err(AgentNetworkError::ResponseTypeMismatch),
                _ => unreachable!(),
            };
            assert_eq!(result.recv().unwrap(), expected, "fault {fault}");
        }
        let input =
            AgentMessage::AuthorityReadBarrierRequest(AuthorityReadBarrierRequest { request });
        let output = AgentMessage::AuthorityReadBarrierReply {
            request,
            barrier: Some(barrier),
        };
        assert!(response_matches_request(&input, &output));
        for message in [&input, &output] {
            assert_eq!(
                AgentTrafficClass::for_message(message),
                AgentTrafficClass::Availability
            );
        }
        assert!(is_request(&input));
        assert!(!is_request(&output));
        assert!(!response_matches_request(
            &input,
            &AgentMessage::Raft(RaftMessage::StatusReply(None))
        ));
    }

    #[test]
    fn cancelled_authority_barrier_receiver_releases_capacity_on_late_reply_or_failure() {
        let pools = new_agent_outbound_permits();
        let peer = key(86).public().to_peer_id();
        let route = test_route(86);
        let request = Hash(id(88));
        let barrier = AuthorityReadBarrier {
            request,
            leader: node(peer),
            raft_term: 3,
            read_index: 7,
            configuration_index: 0,
        };
        let capacity = pools.available(AgentTrafficClass::Availability);
        for late_response in [false, true] {
            let (reply, receiver) = std_mpsc::channel();
            let tracked = TrackedAgentReply {
                pending: PendingAgentReply::AuthorityReadBarrier {
                    meta: PendingMeta {
                        route,
                        target_node: node(peer),
                        target_peer: peer,
                    },
                    request,
                    reply,
                },
                _permit: reserve_agent_outbound_permit(&pools, AgentTrafficClass::Availability)
                    .unwrap(),
            };
            assert_eq!(
                pools.available(AgentTrafficClass::Availability),
                capacity - 1
            );
            drop(receiver);
            if late_response {
                let response = frame(
                    peer,
                    route,
                    AgentMessage::AuthorityReadBarrierReply {
                        request,
                        barrier: Some(barrier),
                    },
                );
                tracked.complete(peer, authenticate_sender(&peer, response).unwrap());
            } else {
                tracked.fail(AgentNetworkError::Timeout);
            }
            assert_eq!(pools.available(AgentTrafficClass::Availability), capacity);
        }
    }

    #[test]
    fn current_applied_availability_requires_exact_identity_claim_and_mode() {
        let peer = key(86).public().to_peer_id();
        let other_peer = key(87).public().to_peer_id();
        let route = test_route(86);
        let request = AppliedAvailabilityRequest {
            raft_index: 7,
            raft_term: 3,
            claim: Hash(id(88)),
        };
        for fault in 0..12 {
            let (reply, result) = std_mpsc::channel();
            let pending = PendingAgentReply::CurrentAppliedAvailability {
                meta: PendingMeta {
                    route,
                    target_node: node(peer),
                    target_peer: peer,
                },
                request,
                reply,
            };
            let mut echoed = request;
            match fault {
                2 => echoed.raft_index += 1,
                3 => echoed.raft_term += 1,
                4 => echoed.claim = Hash(id(89)),
                _ => {}
            }
            let mut response = frame(
                peer,
                route,
                AgentMessage::CurrentAppliedAvailabilityReply {
                    request: echoed,
                    available: fault != 1,
                },
            );
            match fault {
                5 => response.route.space = SpaceId(id(90)),
                6 => response.route.agent = AgentId(id(90)),
                7 => response.route.generation = Hash(id(90)),
                9 => response.sender = node(other_peer),
                10 => {
                    response.message = AgentMessage::Raft(RaftMessage::AppendReply {
                        term: request.raft_term,
                        success: true,
                        match_index: request.raft_index,
                    })
                }
                11 => {
                    response.message = AgentMessage::AppliedAvailabilityReply {
                        request,
                        available: true,
                    }
                }
                _ => {}
            }
            let authenticated =
                authenticate_sender(if fault == 9 { &other_peer } else { &peer }, response)
                    .unwrap();
            pending.complete(if fault == 8 { other_peer } else { peer }, authenticated);
            let expected = match fault {
                0 => Ok(true),
                1 => Ok(false),
                2..=4 => Err(AgentNetworkError::ResponseCorrelationMismatch),
                5..=7 => Err(AgentNetworkError::ResponseRouteMismatch),
                8 => Err(AgentNetworkError::ResponsePeerMismatch),
                9 => Err(AgentNetworkError::ResponseSenderMismatch),
                10 | 11 => Err(AgentNetworkError::ResponseTypeMismatch),
                _ => unreachable!(),
            };
            assert_eq!(result.recv().unwrap(), expected, "fault {fault}");
        }
        let (reply, result) = std_mpsc::channel();
        PendingAgentReply::AppliedAvailability {
            meta: PendingMeta {
                route,
                target_node: node(peer),
                target_peer: peer,
            },
            request,
            reply,
        }
        .complete(
            peer,
            authenticate_sender(
                &peer,
                frame(
                    peer,
                    route,
                    AgentMessage::CurrentAppliedAvailabilityReply {
                        request,
                        available: true,
                    },
                ),
            )
            .unwrap(),
        );
        assert_eq!(
            result.recv().unwrap(),
            Err(AgentNetworkError::ResponseTypeMismatch)
        );
    }

    #[test]
    fn current_applied_availability_is_non_execution_traffic_with_exact_response_matching() {
        let claim = AppliedAvailabilityRequest {
            raft_index: 9,
            raft_term: 2,
            claim: Hash(id(91)),
        };
        let request = AgentMessage::CurrentAppliedAvailabilityRequest(claim);
        assert!(is_request(&request));
        assert_eq!(
            AgentTrafficClass::for_message(&request),
            AgentTrafficClass::Availability
        );
        for available in [false, true] {
            let reply = AgentMessage::CurrentAppliedAvailabilityReply {
                request: claim,
                available,
            };
            assert!(!is_request(&reply));
            assert_eq!(
                AgentTrafficClass::for_message(&reply),
                AgentTrafficClass::Availability
            );
            assert!(response_matches_request(&request, &reply));
            let historical = AgentMessage::AppliedAvailabilityReply {
                request: claim,
                available,
            };
            assert!(!response_matches_request(&request, &historical));
            assert!(!response_matches_request(
                &AgentMessage::AppliedAvailabilityRequest(claim),
                &reply
            ));
        }
        for wrong in [
            AppliedAvailabilityRequest {
                raft_index: 10,
                ..claim
            },
            AppliedAvailabilityRequest {
                raft_term: 3,
                ..claim
            },
            AppliedAvailabilityRequest {
                claim: Hash(id(92)),
                ..claim
            },
        ] {
            assert!(!response_matches_request(
                &request,
                &AgentMessage::CurrentAppliedAvailabilityReply {
                    request: wrong,
                    available: true
                },
            ));
        }
        assert!(!response_matches_request(&request, &request));
    }

    fn invocation_request(
        route: AgentGenerationRoute,
        actor: ActorId,
        invocation: InvocationId,
    ) -> InvocationRequest {
        let work = vos_agent_sdk::InvocationWork {
            space: route.space,
            agent: route.agent,
            runtime_deployment: DeploymentId(id(60)),
            invocation,
            actor,
            incarnation: Hash(id(61)),
            deployment: DeploymentId(id(62)),
            program: ProgramId(id(63)),
            mode: MethodMode::Query,
            origin: InvocationOrigin::anonymous(),
            roles: InvocationRoleClaims::default(),
            message: Vec::new(),
            installation_data: None,
            availability: Vec::new(),
            gas: 10,
            recovery_only: false,
        };
        let public_key = id(64);
        let authority = AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy: Hash(id(65)),
                issuer: AuthorityIssuer {
                    principal: PrincipalId(id(66)),
                    actor: ActorId(id(67)),
                    deployment: DeploymentId(id(68)),
                    program: ProgramId(id(69)),
                    producer: ProducerId::of_public_key(&public_key),
                },
                space: work.space,
                agent: work.agent,
                operation: AuthorityOperationKind::InvokeActor,
                runtime_deployment: work.runtime_deployment,
                actor: Some(work.actor),
                actor_deployment: Some(work.deployment),
                evidence: AuthorityEvidence {
                    package: None,
                    proof: None,
                    commitment: Hash(id(70)),
                },
                lane_roots: AuthorityLaneRoots::default(),
                epoch: 1,
                decision_sequence: 0,
                acknowledged_through: 0,
                valid_from: 1,
                expires_at: 10,
                request: work.commitment(),
            },
            public_key,
            signature: [71; 64],
        };
        InvocationRequest {
            work,
            authorization: InvocationAuthorization::AuthorityReceipt(authority),
        }
    }

    fn invocation_pending(
        peer: PeerId,
        route: AgentGenerationRoute,
        request: InvocationRequest,
    ) -> (
        PendingAgentReply,
        std_mpsc::Receiver<Result<AgentInvocationResponse, AgentNetworkError>>,
    ) {
        let (reply, receiver) = std_mpsc::channel();
        (
            PendingAgentReply::Invocation {
                meta: PendingMeta {
                    route,
                    target_node: node(peer),
                    target_peer: peer,
                },
                request,
                reply,
            },
            receiver,
        )
    }

    #[test]
    fn public_preflight_crosses_canonical_noise_authenticated_ingress() {
        let peer = key(17).public().to_peer_id();
        let route = test_route(18);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let registration = registration(vec![node(peer)], calls.clone());
        let routes = Arc::new(Mutex::new(BTreeMap::from([(
            route,
            Arc::clone(&registration),
        )])));
        let mut request = invocation_request(route, ActorId(id(19)), InvocationId(id(20)));
        request.work.origin = InvocationOrigin {
            principal: Some(PrincipalId(id(21))),
            transport_node: Some(node(peer)),
            credential: Some(vos_agent_sdk::CredentialId(id(22))),
            actor: None,
            capability: None,
        };
        request.work.roles = InvocationRoleClaims::none();
        request.authorization =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&request.work, 23));
        let encoded = frame(peer, route, AgentMessage::InvokeRequest(request))
            .encode()
            .unwrap();
        let decoded = AgentFrame::decode(&encoded).unwrap();
        let (authenticated, admitted) = authorize_inbound(peer, decoded, &routes).unwrap();
        assert!(matches!(
            admitted.handler.handle(authenticated),
            Ok(AgentMessage::Merge(MergeMessage::Heads(_)))
        ));
        assert_eq!(*calls.lock().unwrap(), vec![node(peer)]);
    }

    #[test]
    fn typed_pending_replies_reject_wrong_route_type_invocation_phase_and_hash() {
        let peer = key(3).public().to_peer_id();
        let route = test_route(40);
        let actor = ActorId(id(41));
        let invocation = InvocationId(id(42));
        let request = invocation_request(route, actor, invocation);
        let correlation = invocation_request_correlation(&request);

        let (pending, receiver) = invocation_pending(peer, route, request.clone());
        let response = frame(
            peer,
            test_route(41),
            AgentMessage::InvokeReply(InvocationReply {
                request: correlation,
                outcome: RuntimeOutcome::Completed(Err(vos_agent_sdk::InvocationError::NotFound)),
            }),
        );
        pending.complete(peer, authenticate_sender(&peer, response).unwrap());
        assert_eq!(
            receiver.recv().unwrap(),
            Err(AgentNetworkError::ResponseRouteMismatch)
        );

        let (pending, receiver) = invocation_pending(peer, route, request.clone());
        let response = frame(
            peer,
            route,
            AgentMessage::InvokeReply(InvocationReply {
                request: Hash(id(43)),
                outcome: RuntimeOutcome::Completed(Err(vos_agent_sdk::InvocationError::NotFound)),
            }),
        );
        pending.complete(peer, authenticate_sender(&peer, response).unwrap());
        assert_eq!(
            receiver.recv().unwrap(),
            Err(AgentNetworkError::ResponseCorrelationMismatch)
        );

        let (pending, receiver) = invocation_pending(peer, route, request.clone());
        let response = frame(
            peer,
            route,
            AgentMessage::InvokeReply(InvocationReply {
                request: correlation,
                outcome: RuntimeOutcome::Completed(Ok(vos_agent_sdk::InvocationReply {
                    invocation,
                    actor,
                    incarnation: request.work.incarnation,
                    deployment: request.work.deployment,
                    mode: request.work.mode,
                    lane: Some(vos_agent_sdk::StateLane::Merge),
                    status: vos_agent_sdk::InvocationStatus::Done,
                    reply: Vec::new(),
                    gas_remaining: request.work.gas,
                    observation: vos_agent_sdk::InvocationObservation {
                        linear_revision: None,
                        merge_frontier: None,
                        local_revision: None,
                    },
                })),
            }),
        );
        pending.complete(peer, authenticate_sender(&peer, response).unwrap());
        assert_eq!(
            receiver.recv().unwrap(),
            Err(AgentNetworkError::ResponseCorrelationMismatch),
            "a canonical outcome with a lane inconsistent with the exact work is mismatched"
        );

        let (pending, receiver) = invocation_pending(peer, route, request.clone());
        let response = frame(
            peer,
            route,
            AgentMessage::InvokeReply(InvocationReply {
                request: correlation,
                outcome: RuntimeOutcome::Completed(Ok(vos_agent_sdk::InvocationReply {
                    invocation,
                    actor: ActorId(id(44)),
                    incarnation: request.work.incarnation,
                    deployment: request.work.deployment,
                    mode: request.work.mode,
                    lane: None,
                    status: vos_agent_sdk::InvocationStatus::Done,
                    reply: Vec::new(),
                    gas_remaining: request.work.gas,
                    observation: vos_agent_sdk::InvocationObservation {
                        linear_revision: None,
                        merge_frontier: None,
                        local_revision: None,
                    },
                })),
            }),
        );
        pending.complete(peer, authenticate_sender(&peer, response).unwrap());
        assert_eq!(
            receiver.recv().unwrap(),
            Err(AgentNetworkError::ResponseCorrelationMismatch)
        );

        let (pending, receiver) = invocation_pending(peer, route, request.clone());
        let response = frame(
            peer,
            route,
            AgentMessage::InvokeReply(InvocationReply {
                request: correlation,
                outcome: RuntimeOutcome::Management(Err(
                    vos_agent_sdk::ManagementError::InvalidRequest,
                )),
            }),
        );
        pending.complete(peer, authenticate_sender(&peer, response).unwrap());
        assert_eq!(
            receiver.recv().unwrap(),
            Err(AgentNetworkError::ResponseCorrelationMismatch),
            "a losslessly encoded outcome for another RuntimeWork variant is still mismatched"
        );

        let (reply, receiver) = oneshot::channel();
        let pending = PendingAgentReply::RaftVote {
            meta: PendingMeta {
                route,
                target_node: node(peer),
                target_peer: peer,
            },
            phase: RaftVotePhase::Vote,
            reply,
        };
        let response = frame(
            peer,
            route,
            AgentMessage::Raft(RaftMessage::VoteReply {
                phase: RaftVotePhase::PreVote,
                term: 7,
                granted: true,
            }),
        );
        pending.complete(peer, authenticate_sender(&peer, response).unwrap());
        assert_eq!(
            futures_executor::block_on(receiver).unwrap(),
            Err(AgentNetworkError::ResponseCorrelationMismatch)
        );

        let (reply, receiver) = oneshot::channel();
        let pending = PendingAgentReply::RaftAppend {
            meta: PendingMeta {
                route,
                target_node: node(peer),
                target_peer: peer,
            },
            expected_match_index: 9,
            reply,
        };
        let response = frame(
            peer,
            route,
            AgentMessage::Raft(RaftMessage::AppendReply {
                term: 7,
                success: true,
                match_index: u64::MAX,
            }),
        );
        pending.complete(peer, authenticate_sender(&peer, response).unwrap());
        assert_eq!(
            futures_executor::block_on(receiver).unwrap(),
            Err(AgentNetworkError::ResponseCorrelationMismatch),
            "a voter cannot acknowledge entries outside the exact sent batch"
        );

        let (reply, receiver) = std_mpsc::channel();
        let pending = PendingAgentReply::MergeNode {
            meta: PendingMeta {
                route,
                target_node: node(peer),
                target_peer: peer,
            },
            hash: Hash(id(50)),
            reply,
        };
        let response = frame(
            peer,
            route,
            AgentMessage::Merge(MergeMessage::Node {
                hash: Hash(id(51)),
                bytes: None,
            }),
        );
        pending.complete(peer, authenticate_sender(&peer, response).unwrap());
        assert_eq!(
            receiver.recv().unwrap(),
            Err(AgentNetworkError::ResponseCorrelationMismatch)
        );

        let (reply, receiver) = std_mpsc::channel();
        let pending = PendingAgentReply::MergeHeads {
            meta: PendingMeta {
                route,
                target_node: node(peer),
                target_peer: peer,
            },
            reply,
        };
        let response = frame(
            peer,
            route,
            AgentMessage::Raft(RaftMessage::AppendReply {
                term: 1,
                success: false,
                match_index: 0,
            }),
        );
        pending.complete(peer, authenticate_sender(&peer, response).unwrap());
        assert_eq!(
            receiver.recv().unwrap(),
            Err(AgentNetworkError::ResponseTypeMismatch)
        );
    }

    #[test]
    fn transport_failures_are_stable_and_protocol_specific() {
        assert_eq!(
            outbound_failure(&request_response::OutboundFailure::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "remote inbound stream expired",
            ))),
            AgentNetworkError::Transport
        );
        assert_eq!(
            outbound_failure(&request_response::OutboundFailure::Timeout),
            AgentNetworkError::Timeout
        );
        assert_eq!(
            outbound_failure(&request_response::OutboundFailure::ConnectionClosed),
            AgentNetworkError::Disconnected
        );
        assert_eq!(
            outbound_failure(&request_response::OutboundFailure::DialFailure),
            AgentNetworkError::Disconnected
        );
        assert_eq!(
            outbound_failure(&request_response::OutboundFailure::UnsupportedProtocols),
            AgentNetworkError::UnsupportedProtocol
        );
    }

    #[test]
    fn applied_availability_capacity_is_independent_bounded_and_released() {
        for (permits, application_capacity, availability_capacity, raft_capacity) in [
            (
                new_agent_ingress_permits(),
                MAX_AGENT_INBOUND_APPLICATION_HANDLERS,
                MAX_AGENT_INBOUND_AVAILABILITY_HANDLERS,
                MAX_AGENT_INBOUND_RAFT_HANDLERS,
            ),
            (
                new_agent_outbound_permits(),
                MAX_AGENT_OUTBOUND_APPLICATION_REQUESTS,
                MAX_AGENT_OUTBOUND_AVAILABILITY_REQUESTS,
                MAX_AGENT_OUTBOUND_RAFT_REQUESTS,
            ),
        ] {
            let application = (0..application_capacity)
                .map(|_| permits.try_acquire(AgentTrafficClass::Application).unwrap())
                .collect::<Vec<_>>();
            assert!(permits.try_acquire(AgentTrafficClass::Application).is_err());
            let mut availability = (0..availability_capacity)
                .map(|_| {
                    permits
                        .try_acquire(AgentTrafficClass::Availability)
                        .unwrap()
                })
                .collect::<Vec<_>>();
            assert_eq!(permits.available(AgentTrafficClass::Availability), 0);
            assert_eq!(
                reserve_agent_outbound_permit(&permits, AgentTrafficClass::Availability)
                    .unwrap_err(),
                AgentNetworkError::OutboundCapacity,
            );
            assert_eq!(permits.available(AgentTrafficClass::Raft), raft_capacity);
            let raft = permits.try_acquire(AgentTrafficClass::Raft).unwrap();
            let peer = key(94).public().to_peer_id();
            let route = test_route(94);
            let request = AppliedAvailabilityRequest {
                raft_index: 1,
                raft_term: 1,
                claim: Hash(id(95)),
            };
            for success in [false, true] {
                let (reply, result) = std_mpsc::channel();
                let tracked = TrackedAgentReply {
                    pending: PendingAgentReply::AppliedAvailability {
                        meta: PendingMeta {
                            route,
                            target_node: node(peer),
                            target_peer: peer,
                        },
                        request,
                        reply,
                    },
                    _permit: availability.pop().unwrap(),
                };
                if success {
                    let response = frame(
                        peer,
                        route,
                        AgentMessage::AppliedAvailabilityReply {
                            request,
                            available: true,
                        },
                    );
                    tracked.complete(peer, authenticate_sender(&peer, response).unwrap());
                    assert_eq!(result.recv().unwrap(), Ok(true));
                } else {
                    tracked.fail(AgentNetworkError::Timeout);
                    assert_eq!(result.recv().unwrap(), Err(AgentNetworkError::Timeout));
                }
                assert_eq!(permits.available(AgentTrafficClass::Availability), 1);
                availability.push(
                    permits
                        .try_acquire(AgentTrafficClass::Availability)
                        .unwrap(),
                );
            }
            drop(availability);
            assert_eq!(
                permits.available(AgentTrafficClass::Availability),
                availability_capacity
            );
            assert_eq!(permits.available(AgentTrafficClass::Application), 0);
            drop(application);
            drop(raft);
            assert_eq!(permits.available(AgentTrafficClass::Raft), raft_capacity);
        }
    }

    #[test]
    fn clean_agent_handler_admission_is_hard_bounded() {
        let ingress = new_agent_ingress_permits();
        let mut admitted = Vec::new();
        for _ in 0..MAX_AGENT_INBOUND_APPLICATION_HANDLERS {
            admitted.push(
                ingress
                    .try_acquire(AgentTrafficClass::Application)
                    .expect("declared capacity must be available exactly once"),
            );
        }
        assert_eq!(ingress.available(AgentTrafficClass::Application), 0);
        assert!(ingress.try_acquire(AgentTrafficClass::Application).is_err());
        let raft = ingress
            .try_acquire(AgentTrafficClass::Raft)
            .expect("application saturation must reserve consensus admission");
        assert_eq!(
            ingress.available(AgentTrafficClass::Raft),
            MAX_AGENT_INBOUND_RAFT_HANDLERS - 1
        );
        drop(admitted.pop());
        assert!(ingress.try_acquire(AgentTrafficClass::Application).is_ok());
        drop(raft);
    }

    #[test]
    fn boxed_agent_commands_keep_queue_slots_small_and_release_permits_on_drop() {
        let command_bytes = core::mem::size_of::<NetworkCmd>();
        let request_bytes = core::mem::size_of::<AgentOutboundRequest>();
        assert!(
            command_bytes <= 512,
            "network command grew to {command_bytes} bytes"
        );
        assert!(command_bytes < request_bytes);
        println!("network command bytes={command_bytes}, Agent request bytes={request_bytes}");

        let permits = new_agent_outbound_permits();
        let peer = key(83).public().to_peer_id();
        let route = test_route(83);
        let (reply, receiver) = std_mpsc::channel();
        let request = AgentOutboundRequest {
            peer,
            frame: frame(peer, route, AgentMessage::Merge(MergeMessage::FetchHeads)),
            pending: PendingAgentReply::MergeHeads {
                meta: PendingMeta {
                    route,
                    target_node: node(peer),
                    target_peer: peer,
                },
                reply,
            },
            permit: reserve_agent_outbound_permit(&permits, AgentTrafficClass::Application)
                .unwrap(),
        };
        let (commands, queue) = tokio::sync::mpsc::unbounded_channel();
        assert!(
            commands
                .send(NetworkCmd::SendAgent(Box::new(request)))
                .is_ok()
        );
        assert_eq!(
            permits.available(AgentTrafficClass::Application),
            MAX_AGENT_OUTBOUND_APPLICATION_REQUESTS - 1
        );
        // Dropping the mailbox must drop the entire boxed request, including
        // its exact reply sender and admission permit, without dispatch.
        drop(queue);
        assert_eq!(
            permits.available(AgentTrafficClass::Application),
            MAX_AGENT_OUTBOUND_APPLICATION_REQUESTS
        );
        assert!(matches!(
            receiver.try_recv(),
            Err(std_mpsc::TryRecvError::Disconnected)
        ));
    }

    #[test]
    fn clean_agent_outbound_capacity_is_fail_fast_and_held_until_terminal_result() {
        let permits = new_agent_outbound_permits();
        let peer = key(82).public().to_peer_id();
        let route = test_route(82);
        let meta = PendingMeta {
            route,
            target_node: node(peer),
            target_peer: peer,
        };
        let mut tracked = Vec::new();
        for _ in 0..MAX_AGENT_OUTBOUND_APPLICATION_REQUESTS {
            let permit = reserve_agent_outbound_permit(&permits, AgentTrafficClass::Application)
                .expect("declared outbound capacity must be available exactly once");
            let (reply, _receiver) = std_mpsc::channel();
            tracked.push(TrackedAgentReply {
                pending: PendingAgentReply::MergeHeads { meta, reply },
                _permit: permit,
            });
        }
        assert_eq!(permits.available(AgentTrafficClass::Application), 0);
        assert_eq!(
            reserve_agent_outbound_permit(&permits, AgentTrafficClass::Application).unwrap_err(),
            AgentNetworkError::OutboundCapacity
        );
        let raft = reserve_agent_outbound_permit(&permits, AgentTrafficClass::Raft)
            .expect("application saturation must reserve consensus capacity");
        assert_eq!(
            permits.available(AgentTrafficClass::Raft),
            MAX_AGENT_OUTBOUND_RAFT_REQUESTS - 1
        );

        tracked.pop().unwrap().fail(AgentNetworkError::Timeout);
        assert_eq!(permits.available(AgentTrafficClass::Application), 1);
        let permit =
            reserve_agent_outbound_permit(&permits, AgentTrafficClass::Application).unwrap();
        let (reply, receiver) = std_mpsc::channel();
        let pending = TrackedAgentReply {
            pending: PendingAgentReply::MergeHeads { meta, reply },
            _permit: permit,
        };
        assert_eq!(permits.available(AgentTrafficClass::Application), 0);
        let response = frame(
            peer,
            route,
            AgentMessage::Merge(MergeMessage::Heads(Vec::new())),
        );
        pending.complete(peer, authenticate_sender(&peer, response).unwrap());
        assert_eq!(receiver.recv().unwrap(), Ok(Vec::new()));
        assert_eq!(permits.available(AgentTrafficClass::Application), 1);

        drop(tracked);
        assert_eq!(
            permits.available(AgentTrafficClass::Application),
            MAX_AGENT_OUTBOUND_APPLICATION_REQUESTS
        );
        drop(raft);
        assert_eq!(
            permits.available(AgentTrafficClass::Raft),
            MAX_AGENT_OUTBOUND_RAFT_REQUESTS
        );
    }

    #[test]
    fn live_route_refresh_and_retirement_require_the_exact_handler_owner() {
        let local_key = key(80);
        let local_peer = local_key.public().to_peer_id();
        let local_node = node(local_peer);
        let first_peer = key(81).public().to_peer_id();
        let first_node = node(first_peer);
        let second_peer = key(82).public().to_peer_id();
        let second_node = node(second_peer);
        let route = test_route(80);
        let network = start_network(local_key, Vec::new());
        let first: Arc<dyn AgentRouteHandler> = Arc::new(StaticHandler {
            calls: Arc::new(Mutex::new(Vec::new())),
            response: None,
            delay: None,
        });
        let replacement: Arc<dyn AgentRouteHandler> = Arc::new(StaticHandler {
            calls: Arc::new(Mutex::new(Vec::new())),
            response: None,
            delay: None,
        });

        network
            .install_agent_route(
                route,
                vec![(local_node, local_peer), (first_node, first_peer)],
                Arc::clone(&first),
            )
            .unwrap();
        assert_eq!(
            resolve_peer(&network.agent_peers, first_node),
            Some(first_peer)
        );
        assert_eq!(
            network.install_agent_route(
                route,
                vec![(local_node, local_peer), (second_node, second_peer)],
                Arc::clone(&replacement),
            ),
            Err(AgentNetworkError::RouteAlreadyRegistered)
        );
        assert!(!network.retire_agent_route(route, &replacement));
        assert!(
            network
                .prepare_agent_request(
                    first_node,
                    route,
                    AgentMessage::Merge(MergeMessage::FetchHeads),
                )
                .is_ok()
        );

        // The current owner may atomically refresh its exact committee. A
        // route-owned destination removed from every generation disappears,
        // while the newly admitted full PeerId becomes routable.
        network
            .install_agent_route(
                route,
                vec![(local_node, local_peer), (second_node, second_peer)],
                Arc::clone(&first),
            )
            .unwrap();
        assert_eq!(resolve_peer(&network.agent_peers, first_node), None);
        assert_eq!(
            resolve_peer(&network.agent_peers, second_node),
            Some(second_peer)
        );

        assert!(network.retire_agent_route(route, &first));
        assert_eq!(resolve_peer(&network.agent_peers, second_node), None);
        assert!(matches!(
            network.prepare_agent_request(
                local_node,
                route,
                AgentMessage::Merge(MergeMessage::FetchHeads),
            ),
            Err(AgentNetworkError::UnknownRoute(unknown)) if unknown == route
        ));

        network
            .install_agent_route(
                route,
                vec![(local_node, local_peer), (second_node, second_peer)],
                Arc::clone(&replacement),
            )
            .unwrap();
        // A delayed cleanup from the retired worker cannot revoke the new
        // route owner or its peer binding.
        assert!(!network.retire_agent_route(route, &first));
        assert!(
            network
                .prepare_agent_request(
                    second_node,
                    route,
                    AgentMessage::Merge(MergeMessage::FetchHeads),
                )
                .is_ok()
        );
        assert!(network.retire_agent_route(route, &replacement));
        network.join();
    }

    fn wait_for<T>(mut probe: impl FnMut() -> Option<T>, timeout: Duration) -> Option<T> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(value) = probe() {
                return Some(value);
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn colliding_keys() -> (identity::Keypair, identity::Keypair) {
        let mut by_prefix = BTreeMap::<u16, [u8; 32]>::new();
        for counter in 1u64..=8_192 {
            let mut seed = [0; 32];
            seed[..8].copy_from_slice(&counter.to_le_bytes());
            seed[8..16].copy_from_slice(&counter.rotate_left(17).to_le_bytes());
            seed[16..24].copy_from_slice(&counter.rotate_left(31).to_le_bytes());
            seed[24..].copy_from_slice(&counter.rotate_left(47).to_le_bytes());
            let peer = identity::Keypair::ed25519_from_bytes(seed)
                .unwrap()
                .public()
                .to_peer_id();
            if let Some(previous) = by_prefix.insert(derive_node_prefix(&peer), seed) {
                return (
                    identity::Keypair::ed25519_from_bytes(previous).unwrap(),
                    identity::Keypair::ed25519_from_bytes(seed).unwrap(),
                );
            }
        }
        panic!("deterministic fixture contains no compact collision")
    }

    fn start_network(keypair: identity::Keypair, listen: Vec<Multiaddr>) -> Network {
        let peer = keypair.public().to_peer_id();
        Network::start(NetworkConfig {
            keypair,
            local_prefix: derive_node_prefix(&peer),
            listen,
            bootstrap: Vec::new(),
            auto_dial_mdns: false,
        })
    }

    #[test]
    fn physical_applied_availability_progresses_with_application_outbound_exhausted() {
        let receiver = start_network(key(96), vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()]);
        let address = wait_for(
            || receiver.listen_addrs().into_iter().next(),
            Duration::from_secs(5),
        )
        .expect("availability receiver listens")
        .with(libp2p::multiaddr::Protocol::P2p(receiver.peer_id()));
        let sender = start_network(key(97), Vec::new());
        sender.connect(address);
        let mut members = vec![sender.agent_node_id(), receiver.agent_node_id()];
        members.sort_unstable();
        for network in [&sender, &receiver] {
            network
                .bind_agent_peer(sender.agent_node_id(), sender.peer_id())
                .unwrap();
            network
                .bind_agent_peer(receiver.agent_node_id(), receiver.peer_id())
                .unwrap();
        }
        let request = AppliedAvailabilityRequest {
            raft_index: 11,
            raft_term: 4,
            claim: Hash(id(98)),
        };
        let calls = Arc::new(Mutex::new(Vec::new()));
        let outbound = (0..MAX_AGENT_OUTBOUND_APPLICATION_REQUESTS)
            .map(|_| {
                sender
                    .reserve_agent_outbound(AgentTrafficClass::Application)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        for (current, available) in [(false, false), (false, true), (true, false), (true, true)] {
            let route = test_route(match (current, available) {
                (false, true) => 98,
                (false, false) => 99,
                (true, true) => 100,
                (true, false) => 101,
            });
            let send = if current {
                Network::send_agent_current_applied_availability
            } else {
                Network::send_agent_applied_availability
            };
            for network in [&sender, &receiver] {
                network
                    .register_agent_route(
                        route,
                        members.clone(),
                        Arc::new(StaticHandler {
                            calls: calls.clone(),
                            response: Some(if current {
                                AgentMessage::CurrentAppliedAvailabilityReply { request, available }
                            } else {
                                AgentMessage::AppliedAvailabilityReply { request, available }
                            }),
                            delay: None,
                        }),
                    )
                    .unwrap();
            }
            assert_eq!(
                send(&sender, receiver.agent_node_id(), route, request)
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap(),
                Ok(available),
            );
            assert_eq!(
                send(
                    &sender,
                    receiver.agent_node_id(),
                    route,
                    AppliedAvailabilityRequest {
                        raft_index: 0,
                        ..request
                    }
                )
                .recv_timeout(Duration::from_secs(1))
                .unwrap(),
                Err(AgentNetworkError::InvalidRequest(
                    AgentProtocolError::InvalidValue
                )),
            );
        }
        assert_eq!(*calls.lock().unwrap(), vec![sender.agent_node_id(); 4]);
        assert_eq!(
            sender
                .agent_outbound_permits
                .available(AgentTrafficClass::Application),
            0
        );
        assert_eq!(
            sender
                .agent_outbound_permits
                .available(AgentTrafficClass::Raft),
            MAX_AGENT_OUTBOUND_RAFT_REQUESTS
        );
        drop(outbound);
        sender.join();
        receiver.join();
    }

    #[test]
    fn physical_agent_path_keeps_colliding_peers_distinct_and_fails_closed() {
        let (key_a, key_b) = colliding_keys();
        let peer_a = key_a.public().to_peer_id();
        let peer_b = key_b.public().to_peer_id();
        assert_ne!(peer_a, peer_b);
        assert_eq!(derive_node_prefix(&peer_a), derive_node_prefix(&peer_b));

        let listen: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        let receiver = start_network(key(70), vec![listen]);
        let address = wait_for(
            || receiver.listen_addrs().into_iter().next(),
            Duration::from_secs(5),
        )
        .expect("receiver listens")
        .with(libp2p::multiaddr::Protocol::P2p(receiver.peer_id()));
        let sender_a = start_network(key_a, Vec::new());
        let sender_b = start_network(key_b, Vec::new());
        sender_a.connect(address.clone());
        sender_b.connect(address);

        let route = test_route(60);
        let node_a = sender_a.agent_node_id();
        let node_b = sender_b.agent_node_id();
        let node_receiver = receiver.agent_node_id();
        let mut members = vec![node_a, node_b, node_receiver];
        members.sort_unstable();

        for network in [&receiver, &sender_a, &sender_b] {
            network.bind_agent_peer(node_a, peer_a).unwrap();
            network.bind_agent_peer(node_b, peer_b).unwrap();
            network
                .bind_agent_peer(node_receiver, receiver.peer_id())
                .unwrap();
        }

        let calls = Arc::new(Mutex::new(Vec::new()));
        receiver
            .register_agent_route(
                route,
                members.clone(),
                Arc::new(StaticHandler {
                    calls: calls.clone(),
                    response: Some(AgentMessage::Merge(MergeMessage::Heads(vec![Hash(id(90))]))),
                    delay: None,
                }),
            )
            .unwrap();
        for network in [&sender_a, &sender_b] {
            network
                .register_agent_route(
                    route,
                    members.clone(),
                    Arc::new(StaticHandler {
                        calls: Arc::new(Mutex::new(Vec::new())),
                        response: None,
                        delay: None,
                    }),
                )
                .unwrap();
        }

        let heads_a = sender_a
            .send_agent_merge_fetch_heads(node_receiver, route)
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        let heads_b = sender_b
            .send_agent_merge_fetch_heads(node_receiver, route)
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        assert_eq!(heads_a, vec![Hash(id(90))]);
        assert_eq!(heads_b, heads_a);
        let seen = calls.lock().unwrap().clone();
        assert!(seen.contains(&node_a));
        assert!(seen.contains(&node_b));

        // A valid Noise peer cannot claim the other colliding node.
        sender_a.send_agent_frame_for_test(
            receiver.peer_id(),
            AgentFrame {
                route,
                sender: node_b,
                message: AgentMessage::Merge(MergeMessage::FetchHeads),
            },
        );
        // Nor can it probe an unregistered route or a route where it is not a
        // member.  All three frames are dropped before handler invocation.
        sender_a.send_agent_frame_for_test(
            receiver.peer_id(),
            frame(
                peer_a,
                test_route(61),
                AgentMessage::Merge(MergeMessage::FetchHeads),
            ),
        );
        let receiver_only_route = test_route(62);
        receiver
            .register_agent_route(
                receiver_only_route,
                vec![node_receiver],
                Arc::new(StaticHandler {
                    calls: calls.clone(),
                    response: Some(AgentMessage::Merge(MergeMessage::Heads(Vec::new()))),
                    delay: None,
                }),
            )
            .unwrap();
        sender_a.send_agent_frame_for_test(
            receiver.peer_id(),
            frame(
                peer_a,
                receiver_only_route,
                AgentMessage::Merge(MergeMessage::FetchHeads),
            ),
        );
        sender_a.send_tell(receiver.peer_id(), 1, 2, b"legacy-isolated".to_vec());
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(calls.lock().unwrap().len(), 2);

        // Handler refusal fails within the request deadline, without a legacy
        // fallback or fabricated response. Both peers use the same timeout:
        // inbound stream expiry can reach the requester as an I/O failure
        // before its own outbound timeout fires.
        let timeout_route = test_route(63);
        let refusal_calls = Arc::new(Mutex::new(Vec::new()));
        let mut timeout_members = vec![node_a, node_receiver];
        timeout_members.sort_unstable();
        receiver
            .register_agent_route(
                timeout_route,
                timeout_members.clone(),
                Arc::new(StaticHandler {
                    calls: refusal_calls.clone(),
                    response: None,
                    // Retain the response channel until the protocol deadline
                    // rather than immediately omitting a response.
                    delay: Some(AGENT_REQUEST_TIMEOUT + Duration::from_secs(1)),
                }),
            )
            .unwrap();
        sender_a
            .register_agent_route(
                timeout_route,
                timeout_members,
                Arc::new(StaticHandler {
                    calls: Arc::new(Mutex::new(Vec::new())),
                    response: None,
                    delay: None,
                }),
            )
            .unwrap();
        assert!(matches!(
            sender_a
                .send_agent_merge_fetch_heads(node_receiver, timeout_route)
                .recv_timeout(Duration::from_secs(4))
                .unwrap(),
            Err(AgentNetworkError::Timeout | AgentNetworkError::Transport)
        ));
        assert_eq!(*refusal_calls.lock().unwrap(), vec![node_a]);

        // Oversize and unknown destinations fail locally without touching the
        // swarm.  A bound but unreachable exact PeerId reports disconnect.
        assert!(matches!(
            sender_a
                .send_agent_merge_announce_heads(
                    node_receiver,
                    route,
                    vec![Hash(id(91)); super::super::agent_protocol::MAX_MERGE_HEADS + 1],
                )
                .recv()
                .unwrap(),
            Err(AgentNetworkError::InvalidRequest(_))
        ));

        let ghost_peer = key(71).public().to_peer_id();
        let ghost_node = node(ghost_peer);
        let disconnected_route = test_route(64);
        let mut disconnected_members = vec![node_a, ghost_node];
        disconnected_members.sort_unstable();
        sender_a
            .register_agent_route(
                disconnected_route,
                disconnected_members,
                Arc::new(StaticHandler {
                    calls: Arc::new(Mutex::new(Vec::new())),
                    response: None,
                    delay: None,
                }),
            )
            .unwrap();
        assert_eq!(
            sender_a
                .send_agent_merge_fetch_heads(ghost_node, disconnected_route)
                .recv()
                .unwrap(),
            Err(AgentNetworkError::UnknownDestination(ghost_node))
        );
        sender_a.bind_agent_peer(ghost_node, ghost_peer).unwrap();
        assert_eq!(
            sender_a
                .send_agent_merge_fetch_heads(ghost_node, disconnected_route)
                .recv_timeout(Duration::from_secs(4))
                .unwrap(),
            Err(AgentNetworkError::Disconnected)
        );

        sender_a.join();
        sender_b.join();
        receiver.join();
    }
}
