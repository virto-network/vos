//! Transport trait. Sends Raft RPCs to other replicas and
//! receives their responses.
//!
//! The trait is intentionally minimal: send a request, get a
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
//! Sync API for now. Commit 4 turns these into `async fn`.

use core::fmt::Debug;

use crate::config::NodeId;
use crate::rpc::{
    AppendEntriesReq, AppendEntriesResp, InstallSnapshotReq, InstallSnapshotResp,
    RequestVoteReq, RequestVoteResp,
};

/// Transport for one replication group.
pub trait Transport<N: NodeId>: Send + Sync + 'static {
    type Error: Debug + Send + Sync + 'static;

    /// Send `AppendEntries` to `peer` and block until the reply
    /// arrives (or transport says "no answer"). The worker
    /// invokes this from a helper task in the current
    /// implementation; the upcoming async version invokes it
    /// directly on the worker future and lets the executor
    /// multiplex.
    fn send_append(
        &self,
        peer: N,
        req: AppendEntriesReq<N>,
    ) -> Result<AppendEntriesResp, Self::Error>;

    /// Send `RequestVote` to `peer`.
    fn send_vote(
        &self,
        peer: N,
        req: RequestVoteReq<N>,
    ) -> Result<RequestVoteResp, Self::Error>;

    /// Send `InstallSnapshot` to `peer`. Snapshot bytes are
    /// inside `req.snapshot`; the transport may chunk them as
    /// it sees fit, but the trait method returns once the peer
    /// has applied the *whole* snapshot.
    fn send_install(
        &self,
        peer: N,
        req: InstallSnapshotReq<N>,
    ) -> Result<InstallSnapshotResp, Self::Error>;
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU64, Ordering};

    /// Test transport that records every outbound RPC and
    /// always replies with a fixed canned response. Useful for
    /// unit-testing the worker's outbound logic in isolation.
    pub struct RecordingTransport {
        pub appends: alloc::sync::Arc<std::sync::Mutex<Vec<(u16, AppendEntriesReq<u16>)>>>,
        pub votes: alloc::sync::Arc<std::sync::Mutex<Vec<(u16, RequestVoteReq<u16>)>>>,
        pub installs: alloc::sync::Arc<std::sync::Mutex<Vec<(u16, InstallSnapshotReq<u16>)>>>,
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
        fn send_append(
            &self,
            peer: u16,
            req: AppendEntriesReq<u16>,
        ) -> Result<AppendEntriesResp, Self::Error> {
            let term = self.canned_term.load(Ordering::Relaxed);
            self.appends.lock().unwrap().push((peer, req.clone()));
            Ok(AppendEntriesResp {
                term,
                success: true,
                match_index: req.prev_log_index + req.entries.len() as u64,
            })
        }
        fn send_vote(
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
        fn send_install(
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
