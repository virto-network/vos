//! Clean-generation Agent network protocol boundary.
//!
//! This module defines the Agent-only request/response protocol registered by
//! the clean network path.  It never teaches the legacy `/vos/0.1.0` service
//! codec how to decode Agent traffic.
//!
//! Every route and consensus identity is a full clean SDK identifier.  The
//! `sender` field is only accepted after it is compared with the [`NodeId`]
//! derived from the complete Noise-authenticated [`PeerId`].  No compact node
//! prefix is part of this schema.

use std::fmt;
use std::io;

use async_trait::async_trait;
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::Codec;
use libp2p::{PeerId, StreamProtocol};
use vos_agent_sdk::wire::{
    CanonicalWire, MAX_INVOCATION_AUTHORIZATION_WIRE_BYTES, MAX_RUNTIME_TRANSITION_WIRE_BYTES,
    MAX_RUNTIME_WORK_WIRE_BYTES, WireError,
};
use vos_agent_sdk::{
    ActorId, AgentId, BlobRef, CapabilityId, CredentialId, DeploymentId, Hash,
    InvocationAuthorization, InvocationId, InvocationOrigin, InvocationRoleClaims, InvocationWork,
    MAX_RUNTIME_AVAILABILITY_BYTES, MAX_RUNTIME_AVAILABILITY_ITEMS, MethodMode, NodeId,
    PrincipalId, ProgramId, RoleId, RuntimeBlob, RuntimeOutcome, RuntimeState, RuntimeTransition,
    SpaceId,
};
use vos_protocol::wire::{DecodeError, Decoder, Encoder};

/// The clean Agent protocol is a separate negotiation generation.  It is not
/// a version alias or fallback for `/vos/0.1.0`.
pub(crate) const PROTOCOL: StreamProtocol = StreamProtocol::new("/vos/agent/3.0.0");

// Invocation authorization became an explicit signed-receipt/PublicPreflight
// sum. Keep that incompatible request schema visibly distinct from the prior
// signed-only transport generation; there is no compatibility decoder.
const MAGIC: [u8; 4] = *b"VAN3";
const VERSION: u16 = 3;

pub(crate) const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
/// Enough for one complete clean Ordered command, including its maximum-size
/// `InvocationWork`, journal record, and generation route envelopes.
pub(crate) const MAX_RAFT_COMMAND_BYTES: usize = MAX_RUNTIME_WORK_WIRE_BYTES + 64 * 1024;
pub(crate) const MAX_RAFT_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
/// A Merge event can retain the same maximum-size clean work as an Ordered
/// entry; it must fit as one canonical node without an opaque subframe.
pub(crate) const MAX_MERGE_NODE_BYTES: usize = MAX_RUNTIME_WORK_WIRE_BYTES + 64 * 1024;
pub(crate) const MAX_RAFT_ENTRIES: usize = 256;
/// Full legal Shared-agent committee width; smaller transport-only caps must
/// not make an authority-valid generation impossible to attach.
pub(crate) const MAX_RAFT_MEMBERS: usize = 256;
/// Kept equal to the journal's canonical Merge-frontier bound.  The protocol
/// module is deliberately storage-independent, so repeat the wire constant
/// here and assert equality at the live adapter boundary.
pub(crate) const MAX_MERGE_HEADS: usize = 512;

const _: () = assert!(MAX_RAFT_COMMAND_BYTES + 1024 < MAX_FRAME_BYTES);
const _: () = assert!(MAX_MERGE_NODE_BYTES + 1024 < MAX_FRAME_BYTES);

const TAG_INVOKE_REQUEST: u8 = 0x10;
const TAG_INVOKE_REPLY: u8 = 0x11;
const TAG_INVOKE_REDIRECT: u8 = 0x12;
const TAG_RAFT_APPEND_REQUEST: u8 = 0x20;
const TAG_RAFT_APPEND_REPLY: u8 = 0x21;
const TAG_RAFT_VOTE_REQUEST: u8 = 0x22;
const TAG_RAFT_VOTE_REPLY: u8 = 0x23;
const TAG_RAFT_INSTALL_SNAPSHOT_REQUEST: u8 = 0x24;
const TAG_RAFT_INSTALL_SNAPSHOT_REPLY: u8 = 0x25;
const TAG_RAFT_STATUS_REQUEST: u8 = 0x26;
const TAG_RAFT_STATUS_REPLY: u8 = 0x27;
const TAG_MERGE_FETCH_HEADS: u8 = 0x30;
const TAG_MERGE_HEADS: u8 = 0x31;
const TAG_MERGE_FETCH_NODE: u8 = 0x32;
const TAG_MERGE_NODE: u8 = 0x33;
const TAG_MERGE_ANNOUNCE_HEADS: u8 = 0x34;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AgentProtocolError {
    InvalidMagic,
    UnsupportedVersion(u16),
    UnknownMessage(u8),
    InvalidValue,
    LimitExceeded,
    TrailingBytes,
    Truncated,
    NonCanonical,
    SenderMismatch {
        encoded: NodeId,
        authenticated: NodeId,
    },
}

impl fmt::Display for AgentProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => formatter.write_str("invalid clean Agent protocol magic"),
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported clean Agent protocol version {version}"
                )
            }
            Self::UnknownMessage(tag) => {
                write!(
                    formatter,
                    "unknown clean Agent protocol message tag {tag:#04x}"
                )
            }
            Self::InvalidValue => formatter.write_str("invalid clean Agent protocol value"),
            Self::LimitExceeded => formatter.write_str("clean Agent protocol limit exceeded"),
            Self::TrailingBytes => formatter.write_str("trailing clean Agent protocol bytes"),
            Self::Truncated => formatter.write_str("truncated clean Agent protocol frame"),
            Self::NonCanonical => formatter.write_str("non-canonical clean Agent protocol frame"),
            Self::SenderMismatch {
                encoded,
                authenticated,
            } => write!(
                formatter,
                "encoded Agent sender {encoded:?} does not match Noise-authenticated {authenticated:?}"
            ),
        }
    }
}

impl std::error::Error for AgentProtocolError {}

impl From<DecodeError> for AgentProtocolError {
    fn from(error: DecodeError) -> Self {
        match error {
            DecodeError::Truncated => Self::Truncated,
            DecodeError::LimitExceeded => Self::LimitExceeded,
            DecodeError::TrailingBytes => Self::TrailingBytes,
            DecodeError::NonCanonical => Self::NonCanonical,
            DecodeError::InvalidTag | DecodeError::InvalidPlatform | DecodeError::InvalidUtf8 => {
                Self::InvalidValue
            }
        }
    }
}

impl From<WireError> for AgentProtocolError {
    fn from(error: WireError) -> Self {
        match error {
            WireError::LimitExceeded => Self::LimitExceeded,
            WireError::InvalidValue => Self::InvalidValue,
            WireError::Decode(error) => error.into(),
        }
    }
}

/// Exact route for one admitted Agent replica-set generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct AgentGenerationRoute {
    pub(crate) space: SpaceId,
    pub(crate) agent: AgentId,
    /// Commitment of the admitted complete replica set/committee.
    pub(crate) generation: Hash,
}

impl AgentGenerationRoute {
    pub(crate) fn is_valid(self) -> bool {
        self.space != SpaceId::ZERO && self.agent != AgentId::ZERO && self.generation != Hash::ZERO
    }
}

fn option_nonzero<T: Copy + PartialEq>(value: Option<T>, zero: T) -> bool {
    value.is_none_or(|value| value != zero)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InvocationRequest {
    /// Complete canonical SDK work selected by the authorization.  The
    /// work contains every Principal, Credential, transport Node, Actor, and
    /// invocation identity delivered to the runtime; none is hidden in an
    /// opaque payload.
    pub(crate) work: InvocationWork,
    /// Typed, canonically decoded authorization. This is intentionally not an
    /// opaque subframe: both signed authority receipts and unsigned structural
    /// Public preflights are bound to the complete work before routing.
    pub(crate) authorization: InvocationAuthorization,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InvocationReply {
    /// Domain-separated commitment of the complete work and exact authority
    /// receipt. It binds even error outcomes which carry no identity fields.
    pub(crate) request: Hash,
    /// Lossless canonical SDK outcome. No status, observation, error, yield,
    /// or acknowledgement information is projected away by transport.
    pub(crate) outcome: RuntimeOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InvocationRedirect {
    pub(crate) request: Hash,
    pub(crate) leader: NodeId,
}

pub(crate) fn invocation_request_correlation(request: &InvocationRequest) -> Hash {
    let work = request.work.commitment();
    let authorization = request.authorization.commitment();
    Hash::digest(
        b"vos/agent/network/invocation-correlation/v2",
        &[work.as_bytes(), authorization.as_bytes()],
    )
}

pub(crate) fn outcome_matches_work(outcome: &RuntimeOutcome, work: &InvocationWork) -> bool {
    match outcome {
        RuntimeOutcome::Completed(Ok(reply)) => {
            reply.invocation == work.invocation
                && reply.actor == work.actor
                && reply.incarnation == work.incarnation
                && reply.deployment == work.deployment
                && reply.mode == work.mode
                && reply.lane == work.mode.write_lane()
                && reply.gas_remaining <= work.gas
        }
        RuntimeOutcome::Yielded(yielded) => {
            yielded.invocation == work.invocation
                && yielded.actor == work.actor
                && yielded.incarnation == work.incarnation
                && yielded.deployment == work.deployment
                && yielded.program == work.program
                && yielded.mode == work.mode
        }
        // Canonical invocation errors have no embedded request identities;
        // their exact correlation is the outer request commitment, checked
        // by both inbound and pending-reply paths. Management and
        // acknowledgement outcomes belong to different RuntimeWork variants
        // and are never valid replies to this InvocationWork envelope.
        RuntimeOutcome::Completed(Err(_)) => true,
        RuntimeOutcome::Acknowledged(_) | RuntimeOutcome::Management(_) => false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum RaftVotePhase {
    PreVote = 0,
    Vote = 1,
}

impl RaftVotePhase {
    fn decode(tag: u8) -> Result<Self, AgentProtocolError> {
        match tag {
            0 => Ok(Self::PreVote),
            1 => Ok(Self::Vote),
            _ => Err(AgentProtocolError::NonCanonical),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RaftLogEntryKind {
    /// Application command bytes are opaque to Raft.  Transport identity,
    /// routing, and membership are never taken from this payload.
    Command(Vec<u8>),
    Configuration {
        members: Vec<NodeId>,
        joint_old: Option<Vec<NodeId>>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RaftLogEntry {
    pub(crate) term: u64,
    pub(crate) index: u64,
    pub(crate) kind: RaftLogEntryKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum RaftRole {
    Follower = 0,
    PreCandidate = 1,
    Candidate = 2,
    Leader = 3,
}

impl RaftRole {
    fn decode(tag: u8) -> Result<Self, AgentProtocolError> {
        match tag {
            0 => Ok(Self::Follower),
            1 => Ok(Self::PreCandidate),
            2 => Ok(Self::Candidate),
            3 => Ok(Self::Leader),
            _ => Err(AgentProtocolError::NonCanonical),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RaftStatus {
    pub(crate) role: RaftRole,
    pub(crate) current_term: u64,
    pub(crate) commit_index: u64,
    pub(crate) last_applied: u64,
    pub(crate) last_log_index: u64,
    pub(crate) members: Vec<NodeId>,
    pub(crate) joint_old: Option<Vec<NodeId>>,
    pub(crate) active_config_index: Option<u64>,
    pub(crate) leader: Option<NodeId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RaftMessage {
    AppendRequest {
        term: u64,
        leader: NodeId,
        prev_log_index: u64,
        prev_log_term: u64,
        entries: Vec<RaftLogEntry>,
        leader_commit: u64,
    },
    AppendReply {
        term: u64,
        success: bool,
        match_index: u64,
    },
    VoteRequest {
        phase: RaftVotePhase,
        term: u64,
        candidate: NodeId,
        last_log_index: u64,
        last_log_term: u64,
    },
    VoteReply {
        phase: RaftVotePhase,
        term: u64,
        granted: bool,
    },
    InstallSnapshotRequest {
        term: u64,
        leader: NodeId,
        last_included_index: u64,
        last_included_term: u64,
        offset: u64,
        done: bool,
        members: Vec<NodeId>,
        joint_old: Option<Vec<NodeId>>,
        active_config_index: Option<u64>,
        snapshot: Vec<u8>,
    },
    InstallSnapshotReply {
        term: u64,
        bytes_received: u64,
    },
    StatusRequest,
    StatusReply(Option<RaftStatus>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MergeMessage {
    FetchHeads,
    Heads(Vec<Hash>),
    FetchNode(Hash),
    Node { hash: Hash, bytes: Option<Vec<u8>> },
    AnnounceHeads(Vec<Hash>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AgentMessage {
    InvokeRequest(InvocationRequest),
    InvokeReply(InvocationReply),
    InvokeRedirect(InvocationRedirect),
    Raft(RaftMessage),
    Merge(MergeMessage),
}

/// One decoded clean Agent frame.  It remains untrusted until
/// [`authenticate_sender`] succeeds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AgentFrame {
    pub(crate) route: AgentGenerationRoute,
    pub(crate) sender: NodeId,
    pub(crate) message: AgentMessage,
}

/// A frame whose encoded sender has been bound to the complete
/// Noise-authenticated PeerId.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuthenticatedAgentFrame {
    sender: NodeId,
    frame: AgentFrame,
}

impl AuthenticatedAgentFrame {
    pub(crate) const fn sender(&self) -> NodeId {
        self.sender
    }

    pub(crate) const fn frame(&self) -> &AgentFrame {
        &self.frame
    }

    pub(crate) fn into_frame(self) -> AgentFrame {
        self.frame
    }
}

/// Authenticate a decoded frame before any message payload is dispatched.
///
/// Node identity is derived from all authenticated PeerId bytes.  The helper
/// neither reads nor accepts the legacy compact prefix.
pub(crate) fn authenticate_sender(
    peer: &PeerId,
    frame: AgentFrame,
) -> Result<AuthenticatedAgentFrame, AgentProtocolError> {
    let authenticated = NodeId::of_authenticated_peer(&peer.to_bytes());
    if frame.sender != authenticated {
        return Err(AgentProtocolError::SenderMismatch {
            encoded: frame.sender,
            authenticated,
        });
    }
    Ok(AuthenticatedAgentFrame {
        sender: authenticated,
        frame,
    })
}

impl AgentFrame {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, AgentProtocolError> {
        // Every field has an individual bound, but an AppendEntries request
        // can contain many individually legal maximum-size commands. Reject
        // the aggregate before `Encoder` clones it into an oversized Vec.
        if !message_fits_frame_allocation(&self.message) {
            return Err(AgentProtocolError::LimitExceeded);
        }
        if !self.is_valid() {
            return Err(AgentProtocolError::InvalidValue);
        }

        let mut bytes = Vec::new();
        bytes
            .try_reserve(512)
            .map_err(|_| AgentProtocolError::LimitExceeded)?;
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        let mut encoder = Encoder(&mut bytes);
        encode_route(&mut encoder, self.route);
        encoder.fixed(self.sender.as_bytes());
        encode_message(&mut encoder, &self.message)?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(AgentProtocolError::LimitExceeded);
        }
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, AgentProtocolError> {
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(AgentProtocolError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(MAGIC.len())? != MAGIC {
            return Err(AgentProtocolError::InvalidMagic);
        }
        let version = decoder.u16()?;
        if version != VERSION {
            return Err(AgentProtocolError::UnsupportedVersion(version));
        }
        let route = decode_route(&mut decoder)?;
        let sender = NodeId(decoder.fixed()?);
        let message = decode_message(&mut decoder)?;
        if !decoder.exhausted() {
            return Err(AgentProtocolError::TrailingBytes);
        }
        let frame = Self {
            route,
            sender,
            message,
        };
        if !frame.is_valid() {
            return Err(AgentProtocolError::InvalidValue);
        }
        Ok(frame)
    }

    fn is_valid(&self) -> bool {
        self.route.is_valid()
            && self.sender != NodeId::ZERO
            && message_is_valid(&self.message, self.route, self.sender)
    }
}

fn message_fits_frame_allocation(message: &AgentMessage) -> bool {
    let AgentMessage::Raft(RaftMessage::AppendRequest { entries, .. }) = message else {
        return true;
    };
    // 1 KiB covers the complete fixed frame/route/Raft envelope. Sixty-four
    // bytes per entry covers term/index/tag/list framing; configuration node
    // bytes and command payloads are then accounted exactly. This estimate is
    // intentionally conservative and checked before any aggregate encoding.
    entries
        .iter()
        .try_fold(1_024usize, |total, entry| {
            let body = match &entry.kind {
                RaftLogEntryKind::Command(payload) => payload.len(),
                RaftLogEntryKind::Configuration { members, joint_old } => members
                    .len()
                    .checked_add(joint_old.as_ref().map_or(0, Vec::len))?
                    .checked_mul(32)?,
            };
            total.checked_add(64)?.checked_add(body)
        })
        .is_some_and(|total| total <= MAX_FRAME_BYTES)
}

fn encode_route(encoder: &mut Encoder<'_>, route: AgentGenerationRoute) {
    encoder.fixed(route.space.as_bytes());
    encoder.fixed(route.agent.as_bytes());
    encoder.fixed(route.generation.as_bytes());
}

fn decode_route(decoder: &mut Decoder<'_>) -> Result<AgentGenerationRoute, AgentProtocolError> {
    Ok(AgentGenerationRoute {
        space: SpaceId(decoder.fixed()?),
        agent: AgentId(decoder.fixed()?),
        generation: Hash(decoder.fixed()?),
    })
}

fn message_is_valid(message: &AgentMessage, route: AgentGenerationRoute, sender: NodeId) -> bool {
    match message {
        AgentMessage::InvokeRequest(request) => {
            request.work.validate()
                && request.work.space == route.space
                && request.work.agent == route.agent
                && request.authorization.validate_shape()
                && request.authorization.matches_work(&request.work)
                // The encoded sender becomes trustworthy only after the
                // surrounding frame is matched to the complete Noise PeerId.
                // Once authenticated, an explicitly asserted transport origin
                // must be that exact node; anonymous/actor origins may omit it.
                && request
                    .work
                    .origin
                    .transport_node
                    .is_none_or(|node| node == sender)
        }
        AgentMessage::InvokeReply(reply) => {
            reply.request != Hash::ZERO
                && RuntimeTransition {
                    state: RuntimeState::default(),
                    outcome: reply.outcome.clone(),
                }
                .encode()
                .is_ok()
        }
        AgentMessage::InvokeRedirect(redirect) => {
            redirect.request != Hash::ZERO && redirect.leader != NodeId::ZERO
        }
        AgentMessage::Raft(message) => raft_message_is_valid(message, sender),
        AgentMessage::Merge(message) => merge_message_is_valid(message),
    }
}

fn raft_message_is_valid(message: &RaftMessage, sender: NodeId) -> bool {
    match message {
        RaftMessage::AppendRequest {
            term,
            leader,
            prev_log_index,
            entries,
            ..
        } => {
            *leader == sender
                && entries.len() <= MAX_RAFT_ENTRIES
                && entries.iter().all(raft_entry_is_valid)
                && entries.iter().all(|entry| entry.term <= *term)
                && entries.iter().enumerate().all(|(offset, entry)| {
                    u64::try_from(offset)
                        .ok()
                        .and_then(|offset| prev_log_index.checked_add(offset + 1))
                        == Some(entry.index)
                })
        }
        RaftMessage::AppendReply { .. }
        | RaftMessage::VoteReply { .. }
        | RaftMessage::InstallSnapshotReply { .. }
        | RaftMessage::StatusRequest => true,
        RaftMessage::VoteRequest { candidate, .. } => *candidate == sender,
        RaftMessage::InstallSnapshotRequest {
            leader,
            members,
            joint_old,
            last_included_index,
            active_config_index,
            offset,
            done,
            snapshot,
            ..
        } => {
            *leader == sender
                && u64::try_from(snapshot.len())
                    .ok()
                    .and_then(|length| offset.checked_add(length))
                    .is_some()
                && if *done {
                    if members.is_empty() {
                        joint_old.is_none() && active_config_index.is_none()
                    } else {
                        valid_members(members)
                            && joint_old
                                .as_ref()
                                .is_none_or(|members| valid_members(members))
                            && active_config_index
                                .is_some_and(|index| index <= *last_included_index)
                    }
                } else {
                    members.is_empty() && joint_old.is_none() && active_config_index.is_none()
                }
                && snapshot.len() <= MAX_RAFT_SNAPSHOT_BYTES
        }
        RaftMessage::StatusReply(status) => status
            .as_ref()
            .is_none_or(|status| raft_status_is_valid(status, sender)),
    }
}

fn raft_entry_is_valid(entry: &RaftLogEntry) -> bool {
    if entry.index == 0 {
        return false;
    }
    match &entry.kind {
        RaftLogEntryKind::Command(command) => {
            !command.is_empty() && command.len() <= MAX_RAFT_COMMAND_BYTES
        }
        RaftLogEntryKind::Configuration { members, joint_old } => {
            valid_members(members)
                && joint_old
                    .as_ref()
                    .is_none_or(|members| valid_members(members))
        }
    }
}

fn raft_status_is_valid(status: &RaftStatus, sender: NodeId) -> bool {
    valid_members(&status.members)
        && status
            .joint_old
            .as_ref()
            .is_none_or(|members| valid_members(members))
        && option_nonzero(status.leader, NodeId::ZERO)
        && status.last_applied <= status.commit_index
        && status.commit_index <= status.last_log_index
        && (status.role != RaftRole::Leader || status.leader == Some(sender))
        && status.leader.is_none_or(|leader| {
            status.members.binary_search(&leader).is_ok()
                || status
                    .joint_old
                    .as_ref()
                    .is_some_and(|old| old.binary_search(&leader).is_ok())
        })
}

fn valid_members(members: &[NodeId]) -> bool {
    !members.is_empty()
        && members.len() <= MAX_RAFT_MEMBERS
        && members.iter().all(|member| *member != NodeId::ZERO)
        && members.windows(2).all(|pair| pair[0] < pair[1])
}

fn merge_message_is_valid(message: &MergeMessage) -> bool {
    match message {
        MergeMessage::FetchHeads => true,
        MergeMessage::Heads(heads) | MergeMessage::AnnounceHeads(heads) => valid_heads(heads),
        MergeMessage::FetchNode(hash) => *hash != Hash::ZERO,
        MergeMessage::Node { hash, bytes } => {
            *hash != Hash::ZERO
                && bytes
                    .as_ref()
                    .is_none_or(|bytes| !bytes.is_empty() && bytes.len() <= MAX_MERGE_NODE_BYTES)
        }
    }
}

fn valid_heads(heads: &[Hash]) -> bool {
    heads.len() <= MAX_MERGE_HEADS
        && heads.iter().all(|head| *head != Hash::ZERO)
        && heads.windows(2).all(|pair| pair[0] < pair[1])
}

fn encode_message(
    encoder: &mut Encoder<'_>,
    message: &AgentMessage,
) -> Result<(), AgentProtocolError> {
    match message {
        AgentMessage::InvokeRequest(request) => {
            encoder.u8(TAG_INVOKE_REQUEST);
            encode_invocation_work(encoder, &request.work);
            let authorization = request.authorization.encode()?;
            encoder.bytes(&authorization);
        }
        AgentMessage::InvokeReply(reply) => {
            encoder.u8(TAG_INVOKE_REPLY);
            encoder.fixed(reply.request.as_bytes());
            let canonical = RuntimeTransition {
                state: RuntimeState::default(),
                outcome: reply.outcome.clone(),
            }
            .encode()
            .map_err(AgentProtocolError::from)?;
            encoder.bytes(&canonical);
        }
        AgentMessage::InvokeRedirect(redirect) => {
            encoder.u8(TAG_INVOKE_REDIRECT);
            encoder.fixed(redirect.request.as_bytes());
            encoder.fixed(redirect.leader.as_bytes());
        }
        AgentMessage::Raft(message) => encode_raft_message(encoder, message),
        AgentMessage::Merge(message) => encode_merge_message(encoder, message),
    }
    Ok(())
}

fn encode_invocation_work(encoder: &mut Encoder<'_>, work: &InvocationWork) {
    encoder.fixed(work.space.as_bytes());
    encoder.fixed(work.agent.as_bytes());
    encoder.fixed(work.runtime_deployment.as_bytes());
    encoder.fixed(work.invocation.as_bytes());
    encoder.fixed(work.actor.as_bytes());
    encoder.fixed(work.incarnation.as_bytes());
    encoder.fixed(work.deployment.as_bytes());
    encoder.fixed(work.program.as_bytes());
    encoder.u8(work.mode as u8);
    encode_invocation_origin(encoder, work.origin);
    encode_invocation_roles(encoder, work.roles);
    encoder.bytes(&work.message);
    encode_optional_blob(encoder, &work.installation_data);
    encoder.list(&work.availability, encode_runtime_blob);
    encoder.u64(work.gas);
    encoder.bool(work.recovery_only);
}

fn encode_invocation_origin(encoder: &mut Encoder<'_>, origin: InvocationOrigin) {
    encoder.option(&origin.principal, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
    encoder.option(&origin.transport_node, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
    encoder.option(&origin.credential, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
    encoder.option(&origin.actor, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
    encoder.option(&origin.capability, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
}

fn encode_invocation_roles(encoder: &mut Encoder<'_>, roles: InvocationRoleClaims) {
    encoder.option(&roles.space, |encoder, role| encoder.fixed(role.as_bytes()));
    encoder.option(&roles.actor, |encoder, role| encoder.fixed(role.as_bytes()));
}

fn encode_blob(encoder: &mut Encoder<'_>, blob: &BlobRef) {
    encoder.fixed(blob.hash.as_bytes());
    encoder.u64(blob.len);
}

fn encode_optional_blob(encoder: &mut Encoder<'_>, blob: &Option<BlobRef>) {
    encoder.option(blob, encode_blob);
}

fn encode_runtime_blob(encoder: &mut Encoder<'_>, blob: &RuntimeBlob) {
    encode_blob(encoder, &blob.reference);
    encoder.bytes(&blob.bytes);
}

fn encode_raft_message(encoder: &mut Encoder<'_>, message: &RaftMessage) {
    match message {
        RaftMessage::AppendRequest {
            term,
            leader,
            prev_log_index,
            prev_log_term,
            entries,
            leader_commit,
        } => {
            encoder.u8(TAG_RAFT_APPEND_REQUEST);
            encoder.u64(*term);
            encoder.fixed(leader.as_bytes());
            encoder.u64(*prev_log_index);
            encoder.u64(*prev_log_term);
            encoder.list(entries, encode_raft_entry);
            encoder.u64(*leader_commit);
        }
        RaftMessage::AppendReply {
            term,
            success,
            match_index,
        } => {
            encoder.u8(TAG_RAFT_APPEND_REPLY);
            encoder.u64(*term);
            encoder.bool(*success);
            encoder.u64(*match_index);
        }
        RaftMessage::VoteRequest {
            phase,
            term,
            candidate,
            last_log_index,
            last_log_term,
        } => {
            encoder.u8(TAG_RAFT_VOTE_REQUEST);
            encoder.u8(*phase as u8);
            encoder.u64(*term);
            encoder.fixed(candidate.as_bytes());
            encoder.u64(*last_log_index);
            encoder.u64(*last_log_term);
        }
        RaftMessage::VoteReply {
            phase,
            term,
            granted,
        } => {
            encoder.u8(TAG_RAFT_VOTE_REPLY);
            encoder.u8(*phase as u8);
            encoder.u64(*term);
            encoder.bool(*granted);
        }
        RaftMessage::InstallSnapshotRequest {
            term,
            leader,
            last_included_index,
            last_included_term,
            offset,
            done,
            members,
            joint_old,
            active_config_index,
            snapshot,
        } => {
            encoder.u8(TAG_RAFT_INSTALL_SNAPSHOT_REQUEST);
            encoder.u64(*term);
            encoder.fixed(leader.as_bytes());
            encoder.u64(*last_included_index);
            encoder.u64(*last_included_term);
            encoder.u64(*offset);
            encoder.bool(*done);
            encode_members(encoder, members);
            encoder.option(joint_old, |encoder, members| {
                encode_members(encoder, members)
            });
            encoder.option(active_config_index, |encoder, index| encoder.u64(*index));
            encoder.bytes(snapshot);
        }
        RaftMessage::InstallSnapshotReply {
            term,
            bytes_received,
        } => {
            encoder.u8(TAG_RAFT_INSTALL_SNAPSHOT_REPLY);
            encoder.u64(*term);
            encoder.u64(*bytes_received);
        }
        RaftMessage::StatusRequest => encoder.u8(TAG_RAFT_STATUS_REQUEST),
        RaftMessage::StatusReply(status) => {
            encoder.u8(TAG_RAFT_STATUS_REPLY);
            encoder.option(status, encode_raft_status);
        }
    }
}

fn encode_raft_entry(encoder: &mut Encoder<'_>, entry: &RaftLogEntry) {
    encoder.u64(entry.term);
    encoder.u64(entry.index);
    match &entry.kind {
        RaftLogEntryKind::Command(command) => {
            encoder.u8(0);
            encoder.bytes(command);
        }
        RaftLogEntryKind::Configuration { members, joint_old } => {
            encoder.u8(1);
            encode_members(encoder, members);
            encoder.option(joint_old, |encoder, members| {
                encode_members(encoder, members)
            });
        }
    }
}

fn encode_members(encoder: &mut Encoder<'_>, members: &[NodeId]) {
    encoder.list(members, |encoder, member| encoder.fixed(member.as_bytes()));
}

fn encode_raft_status(encoder: &mut Encoder<'_>, status: &RaftStatus) {
    encoder.u8(status.role as u8);
    encoder.u64(status.current_term);
    encoder.u64(status.commit_index);
    encoder.u64(status.last_applied);
    encoder.u64(status.last_log_index);
    encode_members(encoder, &status.members);
    encoder.option(&status.joint_old, |encoder, members| {
        encode_members(encoder, members)
    });
    encoder.option(&status.active_config_index, |encoder, index| {
        encoder.u64(*index)
    });
    encoder.option(&status.leader, |encoder, leader| {
        encoder.fixed(leader.as_bytes())
    });
}

fn encode_merge_message(encoder: &mut Encoder<'_>, message: &MergeMessage) {
    match message {
        MergeMessage::FetchHeads => encoder.u8(TAG_MERGE_FETCH_HEADS),
        MergeMessage::Heads(heads) => {
            encoder.u8(TAG_MERGE_HEADS);
            encode_heads(encoder, heads);
        }
        MergeMessage::FetchNode(hash) => {
            encoder.u8(TAG_MERGE_FETCH_NODE);
            encoder.fixed(hash.as_bytes());
        }
        MergeMessage::Node { hash, bytes } => {
            encoder.u8(TAG_MERGE_NODE);
            encoder.fixed(hash.as_bytes());
            encoder.option(bytes, |encoder, bytes| encoder.bytes(bytes));
        }
        MergeMessage::AnnounceHeads(heads) => {
            encoder.u8(TAG_MERGE_ANNOUNCE_HEADS);
            encode_heads(encoder, heads);
        }
    }
}

fn encode_heads(encoder: &mut Encoder<'_>, heads: &[Hash]) {
    encoder.list(heads, |encoder, head| encoder.fixed(head.as_bytes()));
}

fn decode_message(decoder: &mut Decoder<'_>) -> Result<AgentMessage, AgentProtocolError> {
    let tag = decoder.u8()?;
    match tag {
        TAG_INVOKE_REQUEST => {
            let work = decode_invocation_work(decoder)?;
            let authorization_wire =
                decoder.bytes_ref_bounded(MAX_INVOCATION_AUTHORIZATION_WIRE_BYTES)?;
            let authorization = InvocationAuthorization::decode(authorization_wire)?;
            Ok(AgentMessage::InvokeRequest(InvocationRequest {
                work,
                authorization,
            }))
        }
        TAG_INVOKE_REPLY => {
            let request = Hash(decoder.fixed()?);
            let canonical = decoder.bytes_ref_bounded(MAX_RUNTIME_TRANSITION_WIRE_BYTES)?;
            let transition = RuntimeTransition::decode(canonical)?;
            if !transition.state.is_empty() {
                return Err(AgentProtocolError::NonCanonical);
            }
            Ok(AgentMessage::InvokeReply(InvocationReply {
                request,
                outcome: transition.outcome,
            }))
        }
        TAG_INVOKE_REDIRECT => {
            let request = Hash(decoder.fixed()?);
            let leader = NodeId(decoder.fixed()?);
            Ok(AgentMessage::InvokeRedirect(InvocationRedirect {
                request,
                leader,
            }))
        }
        TAG_RAFT_APPEND_REQUEST
        | TAG_RAFT_APPEND_REPLY
        | TAG_RAFT_VOTE_REQUEST
        | TAG_RAFT_VOTE_REPLY
        | TAG_RAFT_INSTALL_SNAPSHOT_REQUEST
        | TAG_RAFT_INSTALL_SNAPSHOT_REPLY
        | TAG_RAFT_STATUS_REQUEST
        | TAG_RAFT_STATUS_REPLY => decode_raft_message(tag, decoder).map(AgentMessage::Raft),
        TAG_MERGE_FETCH_HEADS
        | TAG_MERGE_HEADS
        | TAG_MERGE_FETCH_NODE
        | TAG_MERGE_NODE
        | TAG_MERGE_ANNOUNCE_HEADS => decode_merge_message(tag, decoder).map(AgentMessage::Merge),
        _ => Err(AgentProtocolError::UnknownMessage(tag)),
    }
}

fn decode_invocation_work(decoder: &mut Decoder<'_>) -> Result<InvocationWork, DecodeError> {
    let space = SpaceId(decoder.fixed()?);
    let agent = AgentId(decoder.fixed()?);
    let runtime_deployment = DeploymentId(decoder.fixed()?);
    let invocation = InvocationId(decoder.fixed()?);
    let actor = ActorId(decoder.fixed()?);
    let incarnation = Hash(decoder.fixed()?);
    let deployment = DeploymentId(decoder.fixed()?);
    let program = ProgramId(decoder.fixed()?);
    let mode = decode_method_mode(decoder)?;
    let origin = decode_invocation_origin(decoder)?;
    let roles = decode_invocation_roles(decoder, origin)?;
    let message = decoder.bytes_bounded(vos_agent_sdk::MAX_INVOCATION_MESSAGE_BYTES)?;
    let installation_data = decode_optional_blob(decoder)?;
    let availability = decode_runtime_availability(decoder)?;
    let work = InvocationWork {
        space,
        agent,
        runtime_deployment,
        invocation,
        actor,
        incarnation,
        deployment,
        program,
        mode,
        origin,
        roles,
        message,
        installation_data,
        availability,
        gas: decoder.u64()?,
        recovery_only: decoder.bool()?,
    };
    work.validate()
        .then_some(work)
        .ok_or(DecodeError::NonCanonical)
}

fn decode_method_mode(decoder: &mut Decoder<'_>) -> Result<MethodMode, DecodeError> {
    match decoder.u8()? {
        0 => Ok(MethodMode::Query),
        1 => Ok(MethodMode::LinearizableQuery),
        2 => Ok(MethodMode::LocalQuery),
        3 => Ok(MethodMode::Linear),
        4 => Ok(MethodMode::Merge),
        5 => Ok(MethodMode::Local),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn decode_invocation_origin(decoder: &mut Decoder<'_>) -> Result<InvocationOrigin, DecodeError> {
    let origin = InvocationOrigin {
        principal: decoder.option(|decoder| decoder.fixed().map(PrincipalId))?,
        transport_node: decoder.option(|decoder| decoder.fixed().map(NodeId))?,
        credential: decoder.option(|decoder| decoder.fixed().map(CredentialId))?,
        actor: decoder.option(|decoder| decoder.fixed().map(ActorId))?,
        capability: decoder.option(|decoder| decoder.fixed().map(CapabilityId))?,
    };
    origin
        .validate()
        .then_some(origin)
        .ok_or(DecodeError::NonCanonical)
}

fn decode_invocation_roles(
    decoder: &mut Decoder<'_>,
    origin: InvocationOrigin,
) -> Result<InvocationRoleClaims, DecodeError> {
    let roles = InvocationRoleClaims {
        space: decoder.option(|decoder| decoder.fixed().map(RoleId))?,
        actor: decoder.option(|decoder| decoder.fixed().map(RoleId))?,
    };
    roles
        .validate_for(origin)
        .then_some(roles)
        .ok_or(DecodeError::NonCanonical)
}

fn decode_blob(decoder: &mut Decoder<'_>) -> Result<BlobRef, DecodeError> {
    Ok(BlobRef {
        hash: Hash(decoder.fixed()?),
        len: decoder.u64()?,
    })
}

fn decode_optional_blob(decoder: &mut Decoder<'_>) -> Result<Option<BlobRef>, DecodeError> {
    decoder.option(decode_blob)
}

fn decode_runtime_availability(decoder: &mut Decoder<'_>) -> Result<Vec<RuntimeBlob>, DecodeError> {
    let mut remaining = MAX_RUNTIME_AVAILABILITY_BYTES;
    decoder.list_bounded(MAX_RUNTIME_AVAILABILITY_ITEMS, |decoder| {
        let reference = decode_blob(decoder)?;
        let bytes = decoder.bytes_bounded(remaining)?;
        remaining -= bytes.len();
        let blob = RuntimeBlob { reference, bytes };
        blob.validate()
            .then_some(blob)
            .ok_or(DecodeError::NonCanonical)
    })
}

fn decode_raft_message(
    tag: u8,
    decoder: &mut Decoder<'_>,
) -> Result<RaftMessage, AgentProtocolError> {
    match tag {
        TAG_RAFT_APPEND_REQUEST => Ok(RaftMessage::AppendRequest {
            term: decoder.u64()?,
            leader: NodeId(decoder.fixed()?),
            prev_log_index: decoder.u64()?,
            prev_log_term: decoder.u64()?,
            entries: decoder.list_bounded(MAX_RAFT_ENTRIES, |decoder| {
                decode_raft_entry(decoder).map_err(protocol_error_as_decode)
            })?,
            leader_commit: decoder.u64()?,
        }),
        TAG_RAFT_APPEND_REPLY => Ok(RaftMessage::AppendReply {
            term: decoder.u64()?,
            success: decoder.bool()?,
            match_index: decoder.u64()?,
        }),
        TAG_RAFT_VOTE_REQUEST => Ok(RaftMessage::VoteRequest {
            phase: RaftVotePhase::decode(decoder.u8()?)?,
            term: decoder.u64()?,
            candidate: NodeId(decoder.fixed()?),
            last_log_index: decoder.u64()?,
            last_log_term: decoder.u64()?,
        }),
        TAG_RAFT_VOTE_REPLY => Ok(RaftMessage::VoteReply {
            phase: RaftVotePhase::decode(decoder.u8()?)?,
            term: decoder.u64()?,
            granted: decoder.bool()?,
        }),
        TAG_RAFT_INSTALL_SNAPSHOT_REQUEST => {
            let term = decoder.u64()?;
            let leader = NodeId(decoder.fixed()?);
            let last_included_index = decoder.u64()?;
            let last_included_term = decoder.u64()?;
            let offset = decoder.u64()?;
            let done = decoder.bool()?;
            let members = decode_members(decoder)?;
            let joint_old = if decoder.bool()? {
                Some(decode_members(decoder)?)
            } else {
                None
            };
            let active_config_index = decoder.option(Decoder::u64)?;
            let snapshot = decoder.bytes_bounded(MAX_RAFT_SNAPSHOT_BYTES)?;
            Ok(RaftMessage::InstallSnapshotRequest {
                term,
                leader,
                last_included_index,
                last_included_term,
                offset,
                done,
                members,
                joint_old,
                active_config_index,
                snapshot,
            })
        }
        TAG_RAFT_INSTALL_SNAPSHOT_REPLY => Ok(RaftMessage::InstallSnapshotReply {
            term: decoder.u64()?,
            bytes_received: decoder.u64()?,
        }),
        TAG_RAFT_STATUS_REQUEST => Ok(RaftMessage::StatusRequest),
        TAG_RAFT_STATUS_REPLY => {
            let status = if decoder.bool()? {
                Some(decode_raft_status(decoder)?)
            } else {
                None
            };
            Ok(RaftMessage::StatusReply(status))
        }
        _ => Err(AgentProtocolError::UnknownMessage(tag)),
    }
}

fn decode_raft_entry(decoder: &mut Decoder<'_>) -> Result<RaftLogEntry, AgentProtocolError> {
    let term = decoder.u64()?;
    let index = decoder.u64()?;
    let kind = match decoder.u8()? {
        0 => RaftLogEntryKind::Command(decoder.bytes_bounded(MAX_RAFT_COMMAND_BYTES)?),
        1 => {
            let members = decode_members(decoder)?;
            let joint_old = if decoder.bool()? {
                Some(decode_members(decoder)?)
            } else {
                None
            };
            RaftLogEntryKind::Configuration { members, joint_old }
        }
        _ => return Err(AgentProtocolError::NonCanonical),
    };
    Ok(RaftLogEntry { term, index, kind })
}

// `Decoder::list_bounded` deliberately accepts only its base error type.  A
// nested Agent value never maps an identity or limit error to a permissive
// alternative, so the small conversion below preserves fail-closed decoding.
fn protocol_error_as_decode(error: AgentProtocolError) -> DecodeError {
    match error {
        AgentProtocolError::LimitExceeded => DecodeError::LimitExceeded,
        AgentProtocolError::Truncated => DecodeError::Truncated,
        AgentProtocolError::TrailingBytes => DecodeError::TrailingBytes,
        AgentProtocolError::NonCanonical => DecodeError::NonCanonical,
        AgentProtocolError::InvalidMagic
        | AgentProtocolError::UnsupportedVersion(_)
        | AgentProtocolError::UnknownMessage(_)
        | AgentProtocolError::InvalidValue
        | AgentProtocolError::SenderMismatch { .. } => DecodeError::NonCanonical,
    }
}

fn decode_members(decoder: &mut Decoder<'_>) -> Result<Vec<NodeId>, AgentProtocolError> {
    Ok(decoder.list_bounded(MAX_RAFT_MEMBERS, |decoder| decoder.fixed().map(NodeId))?)
}

fn decode_raft_status(decoder: &mut Decoder<'_>) -> Result<RaftStatus, AgentProtocolError> {
    let role = RaftRole::decode(decoder.u8()?)?;
    let current_term = decoder.u64()?;
    let commit_index = decoder.u64()?;
    let last_applied = decoder.u64()?;
    let last_log_index = decoder.u64()?;
    let members = decode_members(decoder)?;
    let joint_old = if decoder.bool()? {
        Some(decode_members(decoder)?)
    } else {
        None
    };
    let active_config_index = decoder.option(Decoder::u64)?;
    let leader = decoder.option(|decoder| decoder.fixed().map(NodeId))?;
    Ok(RaftStatus {
        role,
        current_term,
        commit_index,
        last_applied,
        last_log_index,
        members,
        joint_old,
        active_config_index,
        leader,
    })
}

fn decode_merge_message(
    tag: u8,
    decoder: &mut Decoder<'_>,
) -> Result<MergeMessage, AgentProtocolError> {
    match tag {
        TAG_MERGE_FETCH_HEADS => Ok(MergeMessage::FetchHeads),
        TAG_MERGE_HEADS => decode_heads(decoder).map(MergeMessage::Heads),
        TAG_MERGE_FETCH_NODE => Ok(MergeMessage::FetchNode(Hash(decoder.fixed()?))),
        TAG_MERGE_NODE => {
            let hash = Hash(decoder.fixed()?);
            let bytes = if decoder.bool()? {
                Some(decoder.bytes_bounded(MAX_MERGE_NODE_BYTES)?)
            } else {
                None
            };
            Ok(MergeMessage::Node { hash, bytes })
        }
        TAG_MERGE_ANNOUNCE_HEADS => decode_heads(decoder).map(MergeMessage::AnnounceHeads),
        _ => Err(AgentProtocolError::UnknownMessage(tag)),
    }
}

fn decode_heads(decoder: &mut Decoder<'_>) -> Result<Vec<Hash>, AgentProtocolError> {
    Ok(decoder.list_bounded(MAX_MERGE_HEADS, |decoder| decoder.fixed().map(Hash))?)
}

/// `request_response` codec for the clean protocol.  It is registered only on
/// the dedicated Agent behaviour and is never offered as a legacy fallback.
#[derive(Clone, Default)]
pub(crate) struct AgentCodec;

#[async_trait]
impl Codec for AgentCodec {
    type Protocol = StreamProtocol;
    type Request = AgentFrame;
    type Response = AgentFrame;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io).await
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io).await
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, &request).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, &response).await
    }
}

async fn write_frame<W>(io: &mut W, frame: &AgentFrame) -> io::Result<()>
where
    W: AsyncWrite + Unpin + Send,
{
    let bytes = frame
        .encode()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    io.write_all(&(bytes.len() as u32).to_le_bytes()).await?;
    io.write_all(&bytes).await?;
    io.flush().await
}

async fn read_frame<R>(io: &mut R) -> io::Result<AgentFrame>
where
    R: AsyncRead + Unpin + Send,
{
    let mut length = [0; 4];
    io.read_exact(&mut length).await?;
    let length = u32::from_le_bytes(length) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "clean Agent frame length exceeds cap",
        ));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "clean Agent frame too large"))?;
    bytes.resize(length, 0);
    io.read_exact(&mut bytes).await?;
    AgentFrame::decode(&bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use libp2p::futures::io::Cursor;
    use libp2p::identity::Keypair;
    use vos_agent_sdk::authority::{
        AuthorityEvidence, AuthorityIssuer, AuthorityLaneRoots, AuthorityOperationKind,
        AuthorityReceipt, AuthorityReceiptSelector,
    };
    use vos_agent_sdk::{DeploymentId, ProducerId, ProgramId, PublicPreflight};

    use super::*;

    fn id<const BYTE: u8>() -> [u8; 32] {
        [BYTE; 32]
    }

    fn route() -> AgentGenerationRoute {
        AgentGenerationRoute {
            space: SpaceId(id::<1>()),
            agent: AgentId(id::<2>()),
            generation: Hash(id::<3>()),
        }
    }

    fn peer(seed_byte: u8) -> PeerId {
        Keypair::ed25519_from_bytes([seed_byte; 32])
            .expect("valid deterministic Ed25519 seed")
            .public()
            .to_peer_id()
    }

    fn node(peer: &PeerId) -> NodeId {
        NodeId::of_authenticated_peer(&peer.to_bytes())
    }

    fn receipt(work: &InvocationWork) -> AuthorityReceipt {
        let public_key = id::<41>();
        AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy: Hash(id::<31>()),
                issuer: AuthorityIssuer {
                    principal: PrincipalId(id::<32>()),
                    actor: ActorId(id::<33>()),
                    deployment: DeploymentId(id::<34>()),
                    program: ProgramId(id::<35>()),
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
                    commitment: Hash(id::<38>()),
                },
                lane_roots: AuthorityLaneRoots::default(),
                epoch: 1,
                decision_sequence: 0,
                acknowledged_through: 0,
                valid_from: 4,
                expires_at: 9,
                request: work.commitment(),
            },
            public_key,
            signature: [42; 64],
        }
    }

    fn invoke_frame(peer: &PeerId) -> AgentFrame {
        let route = route();
        let installation_bytes = Vec::new();
        let installation_reference = BlobRef::of_bytes(&installation_bytes);
        let work = InvocationWork {
            space: route.space,
            agent: route.agent,
            runtime_deployment: DeploymentId(id::<36>()),
            invocation: InvocationId(id::<5>()),
            actor: ActorId(id::<4>()),
            incarnation: Hash(id::<43>()),
            deployment: DeploymentId(id::<37>()),
            program: ProgramId(id::<35>()),
            mode: MethodMode::Merge,
            origin: InvocationOrigin {
                principal: Some(PrincipalId(id::<7>())),
                transport_node: Some(node(peer)),
                credential: Some(CredentialId(id::<8>())),
                actor: Some(ActorId(id::<10>())),
                capability: None,
            },
            roles: InvocationRoleClaims {
                space: Some(RoleId(id::<44>())),
                actor: None,
            },
            message: vec![0xaa],
            installation_data: Some(installation_reference.clone()),
            availability: vec![RuntimeBlob {
                reference: installation_reference,
                bytes: installation_bytes,
            }],
            gas: 1_000,
            recovery_only: false,
        };
        let authorization = InvocationAuthorization::AuthorityReceipt(receipt(&work));
        AgentFrame {
            route,
            sender: node(peer),
            message: AgentMessage::InvokeRequest(InvocationRequest {
                work,
                authorization,
            }),
        }
    }

    fn public_invoke_frame(peer: &PeerId, observed_slot: u64) -> AgentFrame {
        let mut frame = invoke_frame(peer);
        let AgentMessage::InvokeRequest(request) = &mut frame.message else {
            unreachable!()
        };
        request.work.roles = InvocationRoleClaims::none();
        request.authorization = InvocationAuthorization::PublicPreflight(
            PublicPreflight::for_work(&request.work, observed_slot),
        );
        frame
    }

    fn round_trip(frame: AgentFrame) {
        let bytes = frame.encode().expect("valid frame encodes");
        assert!(bytes.len() <= MAX_FRAME_BYTES);
        assert_eq!(AgentFrame::decode(&bytes), Ok(frame));
    }

    #[test]
    fn protocol_generation_is_distinct() {
        assert_eq!(PROTOCOL.as_ref(), "/vos/agent/3.0.0");
        assert_ne!(PROTOCOL.as_ref(), "/vos/0.1.0");
    }

    #[test]
    fn invocation_raft_and_merge_families_round_trip_full_ids() {
        let sender_peer = peer(1);
        let sender = node(&sender_peer);
        let member_b = node(&peer(2));
        let mut members = vec![sender, member_b];
        members.sort_unstable();

        let invocation_frame = invoke_frame(&sender_peer);
        let AgentMessage::InvokeRequest(request) = &invocation_frame.message else {
            unreachable!()
        };
        let correlation = invocation_request_correlation(request);
        round_trip(invocation_frame);
        round_trip(AgentFrame {
            route: route(),
            sender,
            message: AgentMessage::InvokeReply(InvocationReply {
                request: correlation,
                outcome: RuntimeOutcome::Completed(Err(vos_agent_sdk::InvocationError::NotFound)),
            }),
        });
        round_trip(AgentFrame {
            route: route(),
            sender,
            message: AgentMessage::InvokeRedirect(InvocationRedirect {
                request: correlation,
                leader: member_b,
            }),
        });
        round_trip(AgentFrame {
            route: route(),
            sender,
            message: AgentMessage::Raft(RaftMessage::AppendRequest {
                term: 7,
                leader: sender,
                prev_log_index: 10,
                prev_log_term: 6,
                entries: vec![
                    RaftLogEntry {
                        term: 7,
                        index: 11,
                        kind: RaftLogEntryKind::Command(b"apply".to_vec()),
                    },
                    RaftLogEntry {
                        term: 7,
                        index: 12,
                        kind: RaftLogEntryKind::Configuration {
                            members: members.clone(),
                            joint_old: Some(vec![sender]),
                        },
                    },
                ],
                leader_commit: 10,
            }),
        });
        round_trip(AgentFrame {
            route: route(),
            sender: member_b,
            message: AgentMessage::Raft(RaftMessage::AppendReply {
                term: 7,
                success: true,
                match_index: 12,
            }),
        });
        round_trip(AgentFrame {
            route: route(),
            sender: member_b,
            message: AgentMessage::Raft(RaftMessage::VoteRequest {
                phase: RaftVotePhase::PreVote,
                term: 8,
                candidate: member_b,
                last_log_index: 12,
                last_log_term: 7,
            }),
        });
        round_trip(AgentFrame {
            route: route(),
            sender,
            message: AgentMessage::Raft(RaftMessage::VoteReply {
                phase: RaftVotePhase::Vote,
                term: 8,
                granted: true,
            }),
        });
        round_trip(AgentFrame {
            route: route(),
            sender,
            message: AgentMessage::Raft(RaftMessage::InstallSnapshotRequest {
                term: 8,
                leader: sender,
                last_included_index: 12,
                last_included_term: 7,
                offset: 0,
                done: true,
                members: members.clone(),
                joint_old: None,
                active_config_index: Some(12),
                snapshot: b"snapshot".to_vec(),
            }),
        });
        round_trip(AgentFrame {
            route: route(),
            sender: member_b,
            message: AgentMessage::Raft(RaftMessage::InstallSnapshotReply {
                term: 8,
                bytes_received: 8,
            }),
        });
        round_trip(AgentFrame {
            route: route(),
            sender,
            message: AgentMessage::Raft(RaftMessage::StatusRequest),
        });
        round_trip(AgentFrame {
            route: route(),
            sender: member_b,
            message: AgentMessage::Raft(RaftMessage::StatusReply(None)),
        });
        round_trip(AgentFrame {
            route: route(),
            sender,
            message: AgentMessage::Raft(RaftMessage::StatusReply(Some(RaftStatus {
                role: RaftRole::Leader,
                current_term: 8,
                commit_index: 12,
                last_applied: 12,
                last_log_index: 12,
                members,
                joint_old: None,
                active_config_index: Some(12),
                leader: Some(sender),
            }))),
        });
        round_trip(AgentFrame {
            route: route(),
            sender,
            message: AgentMessage::Merge(MergeMessage::Node {
                hash: Hash(id::<50>()),
                bytes: Some(b"merge node".to_vec()),
            }),
        });
        round_trip(AgentFrame {
            route: route(),
            sender,
            message: AgentMessage::Merge(MergeMessage::FetchHeads),
        });
        round_trip(AgentFrame {
            route: route(),
            sender,
            message: AgentMessage::Merge(MergeMessage::Heads(vec![Hash(id::<50>())])),
        });
        round_trip(AgentFrame {
            route: route(),
            sender,
            message: AgentMessage::Merge(MergeMessage::FetchNode(Hash(id::<50>()))),
        });
        round_trip(AgentFrame {
            route: route(),
            sender,
            message: AgentMessage::Merge(MergeMessage::AnnounceHeads(vec![Hash(id::<50>())])),
        });
    }

    #[test]
    fn invocation_reply_preserves_every_canonical_outcome_and_rejects_projection_frames() {
        let sender_peer = peer(21);
        let request_frame = invoke_frame(&sender_peer);
        let AgentMessage::InvokeRequest(request) = request_frame.message else {
            unreachable!()
        };
        let correlation = invocation_request_correlation(&request);
        let reply = vos_agent_sdk::InvocationReply {
            invocation: request.work.invocation,
            actor: request.work.actor,
            incarnation: request.work.incarnation,
            deployment: request.work.deployment,
            mode: request.work.mode,
            lane: request.work.mode.write_lane(),
            status: vos_agent_sdk::InvocationStatus::Panicked,
            reply: b"exact panic payload".to_vec(),
            gas_remaining: 17,
            observation: vos_agent_sdk::InvocationObservation {
                linear_revision: Some(11),
                merge_frontier: Some(Hash(id::<52>())),
                local_revision: Some(13),
            },
        };
        let outcomes = vec![
            RuntimeOutcome::Completed(Ok(reply)),
            RuntimeOutcome::Completed(Err(vos_agent_sdk::InvocationError::UnsupportedHostCall(77))),
            RuntimeOutcome::Yielded(vos_agent_sdk::YieldedInvocation {
                invocation: request.work.invocation,
                actor: request.work.actor,
                incarnation: request.work.incarnation,
                deployment: request.work.deployment,
                program: request.work.program,
                mode: request.work.mode,
                continuation: BlobRef {
                    hash: Hash(id::<53>()),
                    len: 9,
                },
                ready_sequence: 3,
                installation_data: None,
                required: Vec::new(),
                reason: vos_agent_sdk::YieldReason::Cooperative,
            }),
            RuntimeOutcome::Management(Err(vos_agent_sdk::ManagementError::InvalidRequest)),
            RuntimeOutcome::Acknowledged(Ok(vos_agent_sdk::InvocationAcknowledgement {
                invocation: request.work.invocation,
                actor: request.work.actor,
                incarnation: request.work.incarnation,
                deployment: request.work.deployment,
                mode: request.work.mode,
                work: request.work.commitment(),
                authorization: request.authorization.commitment(),
            })),
        ];
        for outcome in outcomes {
            let matches_invocation = matches!(
                &outcome,
                RuntimeOutcome::Completed(_) | RuntimeOutcome::Yielded(_)
            );
            assert_eq!(
                outcome_matches_work(&outcome, &request.work),
                matches_invocation
            );
            round_trip(AgentFrame {
                route: route(),
                sender: node(&sender_peer),
                message: AgentMessage::InvokeReply(InvocationReply {
                    request: correlation,
                    outcome,
                }),
            });
        }

        let wrong_lane = RuntimeOutcome::Completed(Ok(vos_agent_sdk::InvocationReply {
            invocation: request.work.invocation,
            actor: request.work.actor,
            incarnation: request.work.incarnation,
            deployment: request.work.deployment,
            mode: request.work.mode,
            lane: Some(vos_agent_sdk::StateLane::Local),
            status: vos_agent_sdk::InvocationStatus::Done,
            reply: Vec::new(),
            gas_remaining: request.work.gas,
            observation: vos_agent_sdk::InvocationObservation {
                linear_revision: None,
                merge_frontier: None,
                local_revision: None,
            },
        }));
        assert!(!outcome_matches_work(&wrong_lane, &request.work));

        let mut oversized = vos_agent_sdk::InvocationReply {
            invocation: request.work.invocation,
            actor: request.work.actor,
            incarnation: request.work.incarnation,
            deployment: request.work.deployment,
            mode: request.work.mode,
            lane: Some(vos_agent_sdk::StateLane::Merge),
            status: vos_agent_sdk::InvocationStatus::Done,
            reply: vec![0; vos_agent_sdk::MAX_INVOCATION_REPLY_BYTES + 1],
            gas_remaining: 1,
            observation: vos_agent_sdk::InvocationObservation {
                linear_revision: None,
                merge_frontier: None,
                local_revision: None,
            },
        };
        let hostile = AgentFrame {
            route: route(),
            sender: node(&sender_peer),
            message: AgentMessage::InvokeReply(InvocationReply {
                request: correlation,
                outcome: RuntimeOutcome::Completed(Ok(oversized.clone())),
            }),
        };
        assert_eq!(hostile.encode(), Err(AgentProtocolError::InvalidValue));
        oversized.reply.clear();

        // The pre-live projected status/payload layout is not a compatibility
        // subframe. Its actor bytes are interpreted as the new request
        // commitment and its invocation prefix as an impossible SDK length.
        let mut previous = Vec::new();
        previous.extend_from_slice(&MAGIC);
        previous.extend_from_slice(&VERSION.to_le_bytes());
        let mut encoder = Encoder(&mut previous);
        encode_route(&mut encoder, route());
        encoder.fixed(node(&sender_peer).as_bytes());
        encoder.u8(TAG_INVOKE_REPLY);
        encoder.fixed(request.work.actor.as_bytes());
        encoder.fixed(request.work.invocation.as_bytes());
        encoder.u8(0);
        encoder.bytes(b"projected");
        assert!(AgentFrame::decode(&previous).is_err());
    }

    #[tokio::test]
    async fn codec_uses_bounded_length_prefix_and_round_trips() {
        let frame = invoke_frame(&peer(3));
        let mut writer = Cursor::new(Vec::new());
        write_frame(&mut writer, &frame).await.unwrap();
        let mut reader = Cursor::new(writer.into_inner());
        assert_eq!(read_frame(&mut reader).await.unwrap(), frame);

        let mut hostile = Cursor::new(((MAX_FRAME_BYTES as u32) + 1).to_le_bytes().to_vec());
        let error = read_frame(&mut hostile).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn authenticated_sender_uses_complete_peer_id_and_rejects_mismatch() {
        let first = peer(4);
        let second = peer(5);
        let frame = invoke_frame(&first);
        let authenticated = authenticate_sender(&first, frame.clone()).unwrap();
        assert_eq!(authenticated.sender(), node(&first));
        assert_eq!(authenticated.frame(), &frame);
        assert_eq!(authenticated.into_frame(), frame.clone());

        assert_eq!(
            authenticate_sender(&second, frame),
            Err(AgentProtocolError::SenderMismatch {
                encoded: node(&first),
                authenticated: node(&second),
            })
        );
    }

    #[test]
    fn full_node_identity_survives_a_compact_hint_collision() {
        let mut by_hint = BTreeMap::new();
        let (first, second, hint) = (1u64..=4_096)
            .find_map(|counter| {
                let mut seed = [0; 32];
                seed[..8].copy_from_slice(&counter.to_le_bytes());
                seed[8..16].copy_from_slice(&counter.rotate_left(17).to_le_bytes());
                seed[16..24].copy_from_slice(&counter.rotate_left(31).to_le_bytes());
                seed[24..].copy_from_slice(&counter.rotate_left(47).to_le_bytes());
                let peer = Keypair::ed25519_from_bytes(seed)
                    .expect("valid deterministic Ed25519 seed")
                    .public()
                    .to_peer_id();
                let hint = compact_test_hint(&peer);
                by_hint
                    .insert(hint, peer)
                    .map(|previous| (previous, peer, hint))
            })
            .expect("deterministic fixture range contains a compact collision");

        assert_ne!(first, second);
        assert_eq!(compact_test_hint(&first), hint);
        assert_eq!(compact_test_hint(&second), hint);
        assert_ne!(node(&first), node(&second));

        let frame = AgentFrame {
            route: route(),
            sender: node(&first),
            message: AgentMessage::Merge(MergeMessage::FetchHeads),
        };
        assert!(authenticate_sender(&first, frame.clone()).is_ok());
        assert!(matches!(
            authenticate_sender(&second, frame),
            Err(AgentProtocolError::SenderMismatch { .. })
        ));
    }

    fn compact_test_hint(peer: &PeerId) -> u16 {
        let hash = blake2b_simd::Params::new()
            .hash_length(2)
            .to_state()
            .update(&peer.to_bytes())
            .finalize();
        u16::from_le_bytes([hash.as_bytes()[0], hash.as_bytes()[1]])
    }

    #[test]
    fn old_unknown_trailing_and_previous_version_frames_fail_closed() {
        let frame = AgentFrame {
            route: route(),
            sender: node(&peer(6)),
            message: AgentMessage::Merge(MergeMessage::FetchHeads),
        };
        let bytes = frame.encode().unwrap();

        let mut old_service_shape = vec![0; bytes.len()];
        old_service_shape[0] = 1;
        assert_eq!(
            AgentFrame::decode(&old_service_shape),
            Err(AgentProtocolError::InvalidMagic)
        );

        let mut projected_agent_v1 = bytes.clone();
        projected_agent_v1[..4].copy_from_slice(b"VAN1");
        projected_agent_v1[4..6].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(
            AgentFrame::decode(&projected_agent_v1),
            Err(AgentProtocolError::InvalidMagic)
        );

        let mut previous_version = bytes.clone();
        previous_version[4..6].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(
            AgentFrame::decode(&previous_version),
            Err(AgentProtocolError::UnsupportedVersion(1))
        );

        let mut unknown = bytes.clone();
        let message_tag_offset = 4 + 2 + 32 * 4;
        unknown[message_tag_offset] = 0xff;
        assert_eq!(
            AgentFrame::decode(&unknown),
            Err(AgentProtocolError::UnknownMessage(0xff))
        );

        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            AgentFrame::decode(&trailing),
            Err(AgentProtocolError::TrailingBytes)
        );
    }

    #[test]
    fn declared_and_actual_oversize_payloads_fail_closed() {
        let sender_peer = peer(7);
        let mut oversized = invoke_frame(&sender_peer);
        let AgentMessage::InvokeRequest(request) = &mut oversized.message else {
            unreachable!();
        };
        request.work.message = vec![0; vos_agent_sdk::MAX_INVOCATION_MESSAGE_BYTES + 1];
        assert_eq!(oversized.encode(), Err(AgentProtocolError::InvalidValue));

        let mut hostile = invoke_frame(&sender_peer).encode().unwrap();
        let message_marker = [1, 0, 0, 0, 0xaa];
        let message_length = hostile
            .windows(message_marker.len())
            .position(|window| window == message_marker)
            .expect("unique actor-message marker");
        hostile[message_length..message_length + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            AgentFrame::decode(&hostile),
            Err(AgentProtocolError::LimitExceeded)
        );

        let oversized_frame = vec![0; MAX_FRAME_BYTES + 1];
        assert_eq!(
            AgentFrame::decode(&oversized_frame),
            Err(AgentProtocolError::LimitExceeded)
        );

        let sender = node(&sender_peer);
        let aggregate = AgentFrame {
            route: route(),
            sender,
            message: AgentMessage::Raft(RaftMessage::AppendRequest {
                term: 1,
                leader: sender,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![
                    RaftLogEntry {
                        term: 1,
                        index: 1,
                        kind: RaftLogEntryKind::Command(vec![0; MAX_FRAME_BYTES / 2]),
                    },
                    RaftLogEntry {
                        term: 1,
                        index: 2,
                        kind: RaftLogEntryKind::Command(vec![0; MAX_FRAME_BYTES / 2]),
                    },
                ],
                leader_commit: 0,
            }),
        };
        assert_eq!(
            aggregate.encode(),
            Err(AgentProtocolError::LimitExceeded),
            "aggregate bounds must reject before encoding individually legal commands"
        );
    }

    #[test]
    fn zero_identities_are_never_encoded_or_decoded() {
        let sender = node(&peer(8));
        let base = AgentFrame {
            route: route(),
            sender,
            message: AgentMessage::InvokeRedirect(InvocationRedirect {
                request: Hash(id::<4>()),
                leader: NodeId(id::<7>()),
            }),
        };

        let mut invalid = base.clone();
        invalid.route.space = SpaceId::ZERO;
        assert_eq!(invalid.encode(), Err(AgentProtocolError::InvalidValue));
        invalid = base.clone();
        invalid.route.agent = AgentId::ZERO;
        assert_eq!(invalid.encode(), Err(AgentProtocolError::InvalidValue));
        invalid = base.clone();
        invalid.route.generation = Hash::ZERO;
        assert_eq!(invalid.encode(), Err(AgentProtocolError::InvalidValue));
        invalid = base.clone();
        invalid.sender = NodeId::ZERO;
        assert_eq!(invalid.encode(), Err(AgentProtocolError::InvalidValue));

        invalid = base.clone();
        let AgentMessage::InvokeRedirect(redirect) = &mut invalid.message else {
            unreachable!();
        };
        redirect.leader = NodeId::ZERO;
        assert_eq!(invalid.encode(), Err(AgentProtocolError::InvalidValue));

        let mut raw = base.encode().unwrap();
        raw[6..38].fill(0);
        assert_eq!(
            AgentFrame::decode(&raw),
            Err(AgentProtocolError::InvalidValue)
        );

        let zero_hash = AgentFrame {
            route: route(),
            sender,
            message: AgentMessage::Merge(MergeMessage::FetchNode(Hash::ZERO)),
        };
        assert_eq!(zero_hash.encode(), Err(AgentProtocolError::InvalidValue));
    }

    #[test]
    fn member_sets_and_heads_have_one_canonical_order() {
        let sender = node(&peer(9));
        let node_a = NodeId(id::<20>());
        let node_b = NodeId(id::<19>());
        let unsorted_members = AgentFrame {
            route: route(),
            sender,
            message: AgentMessage::Raft(RaftMessage::StatusReply(Some(RaftStatus {
                role: RaftRole::Follower,
                current_term: 1,
                commit_index: 0,
                last_applied: 0,
                last_log_index: 0,
                members: vec![node_a, node_b],
                joint_old: None,
                active_config_index: None,
                leader: None,
            }))),
        };
        assert_eq!(
            unsorted_members.encode(),
            Err(AgentProtocolError::InvalidValue)
        );

        let duplicate_heads = AgentFrame {
            route: route(),
            sender,
            message: AgentMessage::Merge(MergeMessage::Heads(vec![
                Hash(id::<21>()),
                Hash(id::<21>()),
            ])),
        };
        assert_eq!(
            duplicate_heads.encode(),
            Err(AgentProtocolError::InvalidValue)
        );

        let canonical = AgentFrame {
            route: route(),
            sender,
            message: AgentMessage::Raft(RaftMessage::StatusReply(Some(RaftStatus {
                role: RaftRole::Follower,
                current_term: 1,
                commit_index: 0,
                last_applied: 0,
                last_log_index: 0,
                members: vec![node_b, node_a],
                joint_old: None,
                active_config_index: None,
                leader: None,
            }))),
        };
        let mut noncanonical_wire = canonical.encode().unwrap();
        let mut member_wire = Vec::new();
        member_wire.extend_from_slice(&2u32.to_le_bytes());
        member_wire.extend_from_slice(node_b.as_bytes());
        member_wire.extend_from_slice(node_a.as_bytes());
        let members_offset = noncanonical_wire
            .windows(member_wire.len())
            .position(|window| window == member_wire)
            .expect("member vector is explicit in the frame");
        let first_member = members_offset + 4;
        noncanonical_wire[first_member..first_member + 32].copy_from_slice(node_a.as_bytes());
        noncanonical_wire[first_member + 32..first_member + 64].copy_from_slice(node_b.as_bytes());
        assert_eq!(
            AgentFrame::decode(&noncanonical_wire),
            Err(AgentProtocolError::InvalidValue)
        );
    }

    #[test]
    fn raft_index_term_snapshot_and_leader_invariants_fail_closed() {
        let sender = node(&peer(12));
        let other = node(&peer(13));
        let mut members = vec![sender, other];
        members.sort_unstable();

        let append = |entry_term, entry_index| AgentFrame {
            route: route(),
            sender,
            message: AgentMessage::Raft(RaftMessage::AppendRequest {
                term: 4,
                leader: sender,
                prev_log_index: 8,
                prev_log_term: 3,
                entries: vec![RaftLogEntry {
                    term: entry_term,
                    index: entry_index,
                    kind: RaftLogEntryKind::Command(vec![1]),
                }],
                leader_commit: 8,
            }),
        };
        assert_eq!(
            append(4, 10).encode(),
            Err(AgentProtocolError::InvalidValue)
        );
        assert_eq!(append(5, 9).encode(), Err(AgentProtocolError::InvalidValue));

        let invalid_snapshot = AgentFrame {
            route: route(),
            sender,
            message: AgentMessage::Raft(RaftMessage::InstallSnapshotRequest {
                term: 4,
                leader: sender,
                last_included_index: 8,
                last_included_term: 3,
                offset: 0,
                done: true,
                members: members.clone(),
                joint_old: None,
                active_config_index: Some(9),
                snapshot: vec![],
            }),
        };
        assert_eq!(
            invalid_snapshot.encode(),
            Err(AgentProtocolError::InvalidValue)
        );

        let invalid_status =
            |role, last_applied, commit_index, last_log_index, leader| AgentFrame {
                route: route(),
                sender,
                message: AgentMessage::Raft(RaftMessage::StatusReply(Some(RaftStatus {
                    role,
                    current_term: 4,
                    commit_index,
                    last_applied,
                    last_log_index,
                    members: members.clone(),
                    joint_old: None,
                    active_config_index: Some(8),
                    leader,
                }))),
            };
        assert_eq!(
            invalid_status(RaftRole::Follower, 9, 8, 10, Some(other)).encode(),
            Err(AgentProtocolError::InvalidValue)
        );
        assert_eq!(
            invalid_status(RaftRole::Follower, 7, 9, 8, Some(other)).encode(),
            Err(AgentProtocolError::InvalidValue)
        );
        assert_eq!(
            invalid_status(RaftRole::Leader, 8, 8, 8, Some(other)).encode(),
            Err(AgentProtocolError::InvalidValue)
        );
    }

    #[test]
    fn exact_invocation_work_authorization_and_transport_binding_is_required() {
        let sender_peer = peer(10);
        let mut missing_principal = invoke_frame(&sender_peer);
        let AgentMessage::InvokeRequest(request) = &mut missing_principal.message else {
            unreachable!();
        };
        request.work.origin.principal = None;
        assert_eq!(
            missing_principal.encode(),
            Err(AgentProtocolError::InvalidValue)
        );

        let mut wrong_route = invoke_frame(&sender_peer);
        let AgentMessage::InvokeRequest(request) = &mut wrong_route.message else {
            unreachable!();
        };
        let InvocationAuthorization::AuthorityReceipt(authority) = &mut request.authorization
        else {
            unreachable!()
        };
        authority.selector.agent = AgentId(id::<99>());
        assert_eq!(wrong_route.encode(), Err(AgentProtocolError::InvalidValue));

        let mut changed_message = invoke_frame(&sender_peer);
        let AgentMessage::InvokeRequest(request) = &mut changed_message.message else {
            unreachable!();
        };
        request.work.message.push(0xbb);
        assert_eq!(
            changed_message.encode(),
            Err(AgentProtocolError::InvalidValue)
        );

        let mut changed_origin = invoke_frame(&sender_peer);
        let AgentMessage::InvokeRequest(request) = &mut changed_origin.message else {
            unreachable!();
        };
        request.work.origin.transport_node = Some(NodeId(id::<77>()));
        assert_eq!(
            changed_origin.encode(),
            Err(AgentProtocolError::InvalidValue)
        );

        let mut changed_deployment = invoke_frame(&sender_peer);
        let AgentMessage::InvokeRequest(request) = &mut changed_deployment.message else {
            unreachable!();
        };
        request.work.deployment = DeploymentId(id::<78>());
        assert_eq!(
            changed_deployment.encode(),
            Err(AgentProtocolError::InvalidValue)
        );

        let mut relayed_public = public_invoke_frame(&sender_peer, 7);
        let AgentMessage::InvokeRequest(request) = &mut relayed_public.message else {
            unreachable!()
        };
        request.work.origin.transport_node = Some(NodeId(id::<79>()));
        request.authorization =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&request.work, 7));
        assert_eq!(
            relayed_public.encode(),
            Err(AgentProtocolError::InvalidValue)
        );

        round_trip(public_invoke_frame(&sender_peer, 7));
    }
}
