//! Operator-tooling senders on [`Network`].
//!
//! Methods that surface the operator/CLI side of the wire protocol —
//! the requests the PVM-actor runtime never originates. The matching
//! *responder* sides (`NetworkService::manifest`, `RaftRpcHandler::handle_join`,
//! `RaftRpcHandler::handle_status`) live in `mod.rs` because a node
//! that's running as a bootnode or cluster member has to answer them
//! as part of its actor-runtime duties.
//!
//! The split is purely organizational — the methods are still on
//! [`Network`] so they can reach the swarm thread via the same
//! private command channel as the actor-runtime senders. Keeping
//! them in a separate file makes the layering visible: anyone reading
//! `mod.rs` sees the actor-runtime API; anyone reading `ops.rs` sees
//! the senders an operator tool (`vosx space up <token>`, future
//! cluster-status reporters) uses to drive a cluster from the outside.

use std::sync::mpsc as std_mpsc;

use libp2p::PeerId;

use super::{ManifestReply, Network, NetworkCmd, RaftJoinResult, RaftStatusReply};

impl Network {
    /// Send a [`Frame::RaftJoinReq`] to a bootnode. The receiver
    /// either calls `change_membership` (returning
    /// [`RaftJoinResult::Accepted`]) or redirects with
    /// [`RaftJoinResult::NotLeader`] + a leader hint. The reply
    /// channel yields exactly once; on transport failure the
    /// Sender is dropped (`recv` yields `Disconnected`).
    ///
    /// Operator-only: invoked by `vosx join` to grow a Raft cluster
    /// at runtime.
    ///
    /// [`Frame::RaftJoinReq`]: super::Frame::RaftJoinReq
    pub fn send_raft_join_req(
        &self,
        target_peer: PeerId,
        replication_id: [u8; 32],
        joiner_prefix: u16,
    ) -> std_mpsc::Receiver<RaftJoinResult> {
        let (tx, rx) = std_mpsc::channel();
        let _ = self.cmd_tx.send(NetworkCmd::SendRaftJoin {
            target_peer,
            replication_id,
            joiner_prefix,
            reply: tx,
        });
        rx
    }

    /// Send a [`Frame::ManifestReq`] to a bootnode. On transport
    /// failure the Sender is dropped.
    ///
    /// Operator-only: invoked by a joining node (`vosx space up
    /// <token>`) when the operator hasn't supplied `--manifest`. The
    /// PVM-actor runtime never originates this — it has its own copy.
    ///
    /// [`Frame::ManifestReq`]: super::Frame::ManifestReq
    pub fn send_manifest_req(&self, target_peer: PeerId) -> std_mpsc::Receiver<ManifestReply> {
        let (tx, rx) = std_mpsc::channel();
        let _ = self.cmd_tx.send(NetworkCmd::SendManifestReq {
            target_peer,
            reply: tx,
        });
        rx
    }

    /// Send a [`Frame::RaftStatusReq`] for one replication
    /// group. The reply describes that peer's view of the
    /// group.
    ///
    /// Operator-only: a cluster-status reporter fans this out
    /// across every connected peer to assemble the snapshot.
    ///
    /// [`Frame::RaftStatusReq`]: super::Frame::RaftStatusReq
    pub fn send_raft_status_req(
        &self,
        target_peer: PeerId,
        replication_id: [u8; 32],
    ) -> std_mpsc::Receiver<RaftStatusReply> {
        let (tx, rx) = std_mpsc::channel();
        let _ = self.cmd_tx.send(NetworkCmd::SendRaftStatus {
            target_peer,
            replication_id,
            reply: tx,
        });
        rx
    }
}
