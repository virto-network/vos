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

    async fn send_append(
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
        // The Network handle returns a sync `std::sync::mpsc::Receiver`.
        // Block on it from a thread-pool task so we don't park the
        // worker future. The `blocking::unblock` adapter is too
        // heavyweight; we use a one-shot tokio-blocking shim
        // adapted as a future via `oneshot`.
        let r = recv_timeout(rx, RPC_TIMEOUT)
            .await
            .ok_or(VosTransportError::NoReply)?;
        Ok(AppendEntriesResp {
            term: r.term,
            success: r.success,
            match_index: r.match_index,
        })
    }

    async fn send_vote(
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
        let r = recv_timeout(rx, RPC_TIMEOUT)
            .await
            .ok_or(VosTransportError::NoReply)?;
        Ok(RequestVoteResp {
            term: r.term,
            vote_granted: r.vote_granted,
        })
    }

    async fn send_install(
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
        let r = recv_timeout(rx, RPC_TIMEOUT)
            .await
            .ok_or(VosTransportError::NoReply)?;
        Ok(InstallSnapshotResp { term: r.term })
    }
}

/// Bridge a sync `std::sync::mpsc::Receiver` into an async future
/// by spawning a short-lived blocking thread that receives with a
/// short polling cadence and forwards the result through a
/// oneshot channel.
///
/// **Why polling, not one big `recv_timeout(2s)`.** The earlier
/// version blocked the helper thread for the full `RPC_TIMEOUT`
/// even when the future had already been dropped (worker
/// shutdown, `FuturesUnordered` discard, election-storm churn).
/// Up to 2s of orphaned threads accumulated under cancellation
/// pressure. The polling loop checks
/// [`futures_channel::oneshot::Sender::is_canceled`] every
/// `POLL_INTERVAL` so a cancelled future drops its helper
/// within tens of milliseconds — bounding the zombie-thread
/// window to a constant regardless of `RPC_TIMEOUT`.
async fn recv_timeout<T: Send + 'static>(
    rx: std::sync::mpsc::Receiver<T>,
    timeout: Duration,
) -> Option<T> {
    /// How often the helper thread checks for cancellation. Short
    /// enough that a dropped future doesn't strand a thread for
    /// long; long enough that `try_recv` overhead is negligible.
    const POLL_INTERVAL: Duration = Duration::from_millis(50);

    let (tx, out) = futures_channel::oneshot::channel();
    std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            // Future was dropped — bail early. This is the whole
            // reason for polling: cancellation lands within
            // POLL_INTERVAL instead of waiting out the full
            // `timeout`.
            if tx.is_canceled() {
                return;
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                let _ = tx.send(None);
                return;
            }
            let wait = (deadline - now).min(POLL_INTERVAL);
            match rx.recv_timeout(wait) {
                Ok(v) => {
                    let _ = tx.send(Some(v));
                    return;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    let _ = tx.send(None);
                    return;
                }
            }
        }
    });
    out.await.ok().flatten()
}
