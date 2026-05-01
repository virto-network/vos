//! Transport trait. Sends Raft RPCs to other replicas and
//! receives their responses.
//!
//! The trait is intentionally minimal: send a request, await a
//! response, period. Implementations decide:
//!
//! - **Routing**. The trait operates on `NodeId`s; the impl
//!   maps those to whatever its native peer identity is
//!   (a libp2p `PeerId`, a UART address byte, a socket).
//! - **Reliability**. Raft tolerates lost / duplicated /
//!   reordered RPCs, so the transport may drop or retry at its
//!   own discretion. A return of `Err(_)` is treated as "no
//!   response" — the worker will retry on the next heartbeat.
//! - **Encoding**. The crate ships pure-data RPC structs;
//!   serialization is the impl's problem.
//!
//! Async API. The worker drives multiple in-flight outbound
//! RPCs from a single task using `FuturesUnordered` — no thread
//! spawning required, so the same code runs on Embassy as on
//! tokio.

use core::fmt::Debug;

use crate::config::NodeId;
use crate::rpc::{
    AppendEntriesReq, AppendEntriesResp, InstallSnapshotReq, InstallSnapshotResp,
    RequestVoteReq, RequestVoteResp,
};

/// Transport for one replication group.
pub trait Transport<N: NodeId>: Send + Sync + 'static {
    type Error: Debug + Send + Sync + 'static;

    /// Send `AppendEntries` to `peer` and await the reply (or a
    /// "no answer" error from the transport).
    fn send_append(
        &self,
        peer: N,
        req: AppendEntriesReq<N>,
    ) -> impl core::future::Future<Output = Result<AppendEntriesResp, Self::Error>> + Send;

    /// Send `RequestVote` to `peer`.
    fn send_vote(
        &self,
        peer: N,
        req: RequestVoteReq<N>,
    ) -> impl core::future::Future<Output = Result<RequestVoteResp, Self::Error>> + Send;

    /// Send `InstallSnapshot` to `peer`. Snapshot bytes are
    /// inside `req.snapshot`; the transport may chunk them as
    /// it sees fit, but the future resolves once the peer has
    /// applied the *whole* snapshot.
    fn send_install(
        &self,
        peer: N,
        req: InstallSnapshotReq<N>,
    ) -> impl core::future::Future<Output = Result<InstallSnapshotResp, Self::Error>> + Send;
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU64, Ordering};

    /// Shared log of recorded RPCs of one variant.
    pub type RpcLog<R> = alloc::sync::Arc<std::sync::Mutex<Vec<(u16, R)>>>;

    /// Test transport that records every outbound RPC and
    /// always replies with a fixed canned response. Useful for
    /// unit-testing the worker's outbound logic in isolation.
    pub struct RecordingTransport {
        pub appends: RpcLog<AppendEntriesReq<u16>>,
        pub votes: RpcLog<RequestVoteReq<u16>>,
        pub installs: RpcLog<InstallSnapshotReq<u16>>,
        pub canned_term: AtomicU64,
    }

    impl Default for RecordingTransport {
        fn default() -> Self {
            Self {
                appends: Default::default(),
                votes: Default::default(),
                installs: Default::default(),
                canned_term: AtomicU64::new(0),
            }
        }
    }

    impl Transport<u16> for RecordingTransport {
        type Error = core::convert::Infallible;
        async fn send_append(
            &self,
            peer: u16,
            req: AppendEntriesReq<u16>,
        ) -> Result<AppendEntriesResp, Self::Error> {
            let term = self.canned_term.load(Ordering::Relaxed);
            let len = req.entries.len() as u64;
            let prev = req.prev_log_index;
            self.appends.lock().unwrap().push((peer, req));
            Ok(AppendEntriesResp {
                term,
                success: true,
                match_index: prev + len,
            })
        }
        async fn send_vote(
            &self,
            peer: u16,
            req: RequestVoteReq<u16>,
        ) -> Result<RequestVoteResp, Self::Error> {
            let term = self.canned_term.load(Ordering::Relaxed);
            self.votes.lock().unwrap().push((peer, req));
            Ok(RequestVoteResp {
                term,
                vote_granted: true,
            })
        }
        async fn send_install(
            &self,
            peer: u16,
            req: InstallSnapshotReq<u16>,
        ) -> Result<InstallSnapshotResp, Self::Error> {
            let term = self.canned_term.load(Ordering::Relaxed);
            self.installs.lock().unwrap().push((peer, req));
            Ok(InstallSnapshotResp { term })
        }
    }
}
