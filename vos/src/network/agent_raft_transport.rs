//! `vos_raft::Transport<NodeId>` over the clean Agent request path.
//!
//! This adapter is intentionally separate from the legacy compact-u16
//! transport.  Every destination is resolved through the clean bijective
//! NodeId/PeerId directory and every reply passes the typed Agent correlation
//! checks before it reaches the Raft worker.

use std::sync::Arc;

use vos_agent_sdk::NodeId;
use vos_raft::{
    AppendEntriesReq, AppendEntriesResp, InstallSnapshotReq, InstallSnapshotResp, PreVoteReq,
    PreVoteResp, RequestVoteReq, RequestVoteResp, Transport,
};

use super::Network;
use super::agent_network::AgentNetworkError;
use super::agent_protocol::{
    AgentFrame, AgentGenerationRoute, AgentMessage, AgentProtocolError, MAX_RAFT_ENTRIES,
    RaftLogEntry, RaftLogEntryKind, RaftMessage, RaftVotePhase,
};

#[derive(Debug)]
pub(crate) enum AgentRaftTransportError {
    Network(AgentNetworkError),
    NoReply,
    EntryTooLarge,
    UnsupportedEntryKind,
}

impl core::fmt::Display for AgentRaftTransportError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Network(error) => write!(formatter, "clean Agent Raft transport: {error}"),
            Self::NoReply => {
                formatter.write_str("clean Agent Raft transport: reply channel closed")
            }
            Self::EntryTooLarge => {
                formatter.write_str("clean Agent Raft transport: one entry exceeds frame bounds")
            }
            Self::UnsupportedEntryKind => {
                formatter.write_str("clean Agent Raft transport: unsupported entry kind")
            }
        }
    }
}

impl std::error::Error for AgentRaftTransportError {}

/// One clean Raft transport per exact Agent generation route.
pub(crate) struct AgentRaftTransport {
    network: Arc<Network>,
    route: AgentGenerationRoute,
}

impl AgentRaftTransport {
    pub(crate) fn new(network: Arc<Network>, route: AgentGenerationRoute) -> Self {
        Self { network, route }
    }

    fn append_fits(&self, message: &RaftMessage) -> Result<bool, AgentRaftTransportError> {
        let frame = AgentFrame {
            route: self.route,
            sender: self.network.agent_node_id(),
            message: AgentMessage::Raft(message.clone()),
        };
        match frame.encode() {
            Ok(_) => Ok(true),
            Err(AgentProtocolError::LimitExceeded) => Ok(false),
            Err(error) => Err(AgentRaftTransportError::Network(
                AgentNetworkError::InvalidRequest(error),
            )),
        }
    }
}

impl Transport<NodeId> for AgentRaftTransport {
    type Error = AgentRaftTransportError;

    async fn send_append(
        &self,
        peer: NodeId,
        request: AppendEntriesReq<NodeId>,
    ) -> Result<AppendEntriesResp, Self::Error> {
        let mut entries = request
            .entries
            .into_iter()
            .map(|entry| {
                let kind = match entry.kind {
                    vos_raft::EntryKind::Data { payload } => RaftLogEntryKind::Command(payload),
                    vos_raft::EntryKind::ConfigChange { members, joint_old } => {
                        RaftLogEntryKind::Configuration { members, joint_old }
                    }
                    _ => return Err(AgentRaftTransportError::UnsupportedEntryKind),
                };
                Ok(RaftLogEntry {
                    term: entry.term,
                    index: entry.index,
                    kind,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        entries.truncate(MAX_RAFT_ENTRIES);

        let mut message = RaftMessage::AppendRequest {
            term: request.term,
            leader: request.leader,
            prev_log_index: request.prev_log_index,
            prev_log_term: request.prev_log_term,
            entries,
            leader_commit: request.leader_commit,
        };
        loop {
            if self.append_fits(&message)? {
                break;
            }
            let RaftMessage::AppendRequest { entries, .. } = &mut message else {
                unreachable!();
            };
            if entries.len() <= 1 {
                return Err(AgentRaftTransportError::EntryTooLarge);
            }
            entries.pop();
        }

        let response = receive(
            self.network
                .send_agent_raft_append(peer, self.route, message),
        )
        .await?;
        Ok(AppendEntriesResp {
            term: response.term,
            success: response.success,
            match_index: response.match_index,
        })
    }

    async fn send_vote(
        &self,
        peer: NodeId,
        request: RequestVoteReq<NodeId>,
    ) -> Result<RequestVoteResp, Self::Error> {
        let response = receive(self.network.send_agent_raft_vote(
            peer,
            self.route,
            RaftMessage::VoteRequest {
                phase: RaftVotePhase::Vote,
                term: request.term,
                candidate: request.candidate,
                last_log_index: request.last_log_index,
                last_log_term: request.last_log_term,
            },
        ))
        .await?;
        Ok(RequestVoteResp {
            term: response.term,
            vote_granted: response.granted,
        })
    }

    async fn send_prevote(
        &self,
        peer: NodeId,
        request: PreVoteReq<NodeId>,
    ) -> Result<PreVoteResp, Self::Error> {
        let response = receive(self.network.send_agent_raft_vote(
            peer,
            self.route,
            RaftMessage::VoteRequest {
                phase: RaftVotePhase::PreVote,
                term: request.next_term,
                candidate: request.candidate,
                last_log_index: request.last_log_index,
                last_log_term: request.last_log_term,
            },
        ))
        .await?;
        Ok(PreVoteResp {
            term: response.term,
            vote_granted: response.granted,
        })
    }

    async fn send_install(
        &self,
        peer: NodeId,
        request: InstallSnapshotReq<NodeId>,
    ) -> Result<InstallSnapshotResp, Self::Error> {
        let response = receive(self.network.send_agent_raft_install_snapshot(
            peer,
            self.route,
            RaftMessage::InstallSnapshotRequest {
                term: request.term,
                leader: request.leader,
                last_included_index: request.last_included_index,
                last_included_term: request.last_included_term,
                offset: request.offset,
                done: request.done,
                members: request.members,
                joint_old: request.joint_old,
                active_config_index: request.active_config_index,
                snapshot: request.data,
            },
        ))
        .await?;
        Ok(InstallSnapshotResp {
            term: response.term,
            bytes_received: response.bytes_received,
        })
    }
}

async fn receive<T>(
    receiver: futures_channel::oneshot::Receiver<Result<T, AgentNetworkError>>,
) -> Result<T, AgentRaftTransportError> {
    match receiver.await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(AgentRaftTransportError::Network(error)),
        Err(_) => Err(AgentRaftTransportError::NoReply),
    }
}
