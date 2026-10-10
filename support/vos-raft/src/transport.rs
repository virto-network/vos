//! How the driver reaches other replicas: one-way and best-effort. The
//! protocol tolerates loss, duplication and reordering; a transport needs
//! only to deliver what it can, and to name the sender truthfully.

use crate::config::NodeId;
use crate::message::Message;
use crate::rpc::{InstallSnapshotReq, InstallSnapshotResp};

/// What travels between replicas: a protocol message, or a piece of a
/// snapshot transfer, which the driver runs outside the protocol core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Envelope<N: NodeId> {
    Raft(Message<N>),
    SnapshotChunk(InstallSnapshotReq<N>),
    SnapshotAck(InstallSnapshotResp),
}

pub trait Transport<N: NodeId>: Send + Sync + 'static {
    /// Send `envelope` from `from` to `to`, without waiting.
    fn send(&self, from: N, to: N, envelope: Envelope<N>);
}
