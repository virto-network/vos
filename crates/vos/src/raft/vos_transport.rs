//! `vos_raft::Transport<u16>` adapter backed by [`Network`].
//!
//! Bridges the generic Raft core's outbound RPC trait to vos's
//! libp2p-based [`Network::send_raft_append`] /
//! [`Network::send_raft_vote`] /
//! [`Network::send_raft_install_snapshot`] calls. The trait is sync
//! (a later vos-raft commit makes it `async`), so this adapter blocks
//! on the per-call reply channel up to a fixed timeout — same shape
//! the inline worker used pre-extraction.
//!
//! ## Identity mapping
//!
//! vos addresses peers by their 16-bit `node_prefix`, not by libp2p
//! `PeerId`. The adapter resolves the prefix through
//! [`Network::peer_for_prefix`] on every call. A peer that hasn't
//! exchanged a `Hello` frame with us yet (so its prefix isn't in the
//! map) surfaces as a transport error — Raft tolerates that the same
//! way it would tolerate a dropped packet.
//!
//! [`Network::send_raft_append`]: crate::network::Network::send_raft_append
//! [`Network::send_raft_vote`]: crate::network::Network::send_raft_vote
//! [`Network::send_raft_install_snapshot`]: crate::network::Network::send_raft_install_snapshot
//! [`Network::peer_for_prefix`]: crate::network::Network::peer_for_prefix

use alloc::sync::Arc;
use core::time::Duration;

use vos_raft::{
    AppendEntriesReq, AppendEntriesResp, InstallSnapshotReq, InstallSnapshotResp,
    RequestVoteReq, RequestVoteResp, Transport,
};

use crate::network::{Network, RaftEntry};

/// Per-RPC timeout for the libp2p reply channel. Long enough that a
/// healthy peer always answers in time, short enough that a hung
/// connection doesn't strand the worker for the lifetime of the
/// process. The election timer fires well before this, so a peer
/// that exceeds the cap is already being treated as unreachable
/// upstream.
const RPC_TIMEOUT: Duration = Duration::from_secs(2);

/// Reasons the libp2p side couldn't deliver an outbound RPC.
#[derive(Debug)]
pub enum VosTransportError {
    /// We don't have a `PeerId` for `peer_prefix` yet — typically
    /// because the Hello handshake hasn't completed. Worker treats
    /// this the same as a dropped packet (it'll retry on the next
    /// heartbeat tick).
    UnknownPeer(u16),
    /// The reply channel disconnected or timed out before yielding
    /// a response. Treated as "no answer" by the worker.
    NoReply,
}

impl core::fmt::Display for VosTransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownPeer(p) => {
                write!(f, "vos transport: no PeerId mapped for prefix {p:04x}")
            }
            Self::NoReply => write!(f, "vos transport: no reply within timeout"),
        }
    }
}

impl std::error::Error for VosTransportError {}

/// `vos_raft::Transport<u16>` impl that ferries RPCs through a
/// shared [`Arc<Network>`]. Construct one per replication group —
/// the `replication_id` is captured at build time so the trait
/// methods don't need to take it.
pub struct VosTransport {
    network: Arc<Network>,
    replication_id: [u8; 32],
}

impl VosTransport {
    /// Build a `VosTransport` for one replication group on the
    /// given network handle. `replication_id` is the 32-byte group
    /// key the cluster shares.
    pub fn new(network: Arc<Network>, replication_id: [u8; 32]) -> Self {
        Self {
            network,
            replication_id,
        }
    }
}

impl Transport<u16> for VosTransport {
    type Error = VosTransportError;

    fn send_append(
        &self,
        peer: u16,
        req: AppendEntriesReq<u16>,
    ) -> Result<AppendEntriesResp, Self::Error> {
        let peer_id = self
            .network
            .peer_for_prefix(peer)
            .ok_or(VosTransportError::UnknownPeer(peer))?;
        let entries = req
            .entries
            .into_iter()
            .map(|e| RaftEntry {
                term: e.term,
                payload: e.payload,
            })
            .collect();
        let rx = self.network.send_raft_append(
            peer_id,
            self.replication_id,
            req.term,
            req.leader,
            req.prev_log_index,
            req.prev_log_term,
            req.leader_commit,
            entries,
        );
        let r = rx
            .recv_timeout(RPC_TIMEOUT)
            .map_err(|_| VosTransportError::NoReply)?;
        Ok(AppendEntriesResp {
            term: r.term,
            success: r.success,
            match_index: r.match_index,
        })
    }

    fn send_vote(
        &self,
        peer: u16,
        req: RequestVoteReq<u16>,
    ) -> Result<RequestVoteResp, Self::Error> {
        let peer_id = self
            .network
            .peer_for_prefix(peer)
            .ok_or(VosTransportError::UnknownPeer(peer))?;
        let rx = self.network.send_raft_vote(
            peer_id,
            self.replication_id,
            req.term,
            req.candidate,
            req.last_log_index,
            req.last_log_term,
        );
        let r = rx
            .recv_timeout(RPC_TIMEOUT)
            .map_err(|_| VosTransportError::NoReply)?;
        Ok(RequestVoteResp {
            term: r.term,
            vote_granted: r.vote_granted,
        })
    }

    fn send_install(
        &self,
        peer: u16,
        req: InstallSnapshotReq<u16>,
    ) -> Result<InstallSnapshotResp, Self::Error> {
        let peer_id = self
            .network
            .peer_for_prefix(peer)
            .ok_or(VosTransportError::UnknownPeer(peer))?;
        let rx = self.network.send_raft_install_snapshot(
            peer_id,
            self.replication_id,
            req.term,
            req.leader,
            req.last_included_index,
            req.last_included_term,
            req.snapshot,
        );
        let r = rx
            .recv_timeout(RPC_TIMEOUT)
            .map_err(|_| VosTransportError::NoReply)?;
        Ok(InstallSnapshotResp { term: r.term })
    }
}
