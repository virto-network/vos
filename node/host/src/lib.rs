//! The VOS node host: its storage and, on one process, every agent it
//! runs (`Node`).

pub mod blobs;
pub mod client;
mod dispatch;
mod executor;
mod group;
pub mod http;
mod ingress;
mod leader;
mod node;
pub mod peer;
mod pvm;
pub mod raft;
pub mod space;
pub mod storage;
pub mod store;
pub mod tls;

pub use node::{ADMIN_TOKEN, CallError, Config, Error, NODE_KEY, Node, Peers, Reply, wall_clock};
pub use space::{Space, SpaceNode};

use vos_wire::Encode;
use vos_wire::batch::Batch;
use vos_wire::ids::AgentId;
use vos_wire::peer::CreationRecord;

/// The identity of the agent `record` creates: its record's hash. Clients
/// sign for it, and its replica group is named by it.
pub fn identity(record: &CreationRecord) -> [u8; 32] {
    vos_pvm::precompile::blake2b_256(&record.encode())
}

/// Points where a test breaks the node as a crash or a bug would.
pub trait Hooks: Send + Sync {
    /// Before the storage thread commits what is queued: a test can hold
    /// every commit here.
    fn before_commit(&self) {}

    /// After `agent`'s commit of log index `index`, before it answers or
    /// sends anything: false stops its leader there.
    fn after_commit(&self, agent: AgentId, index: u64) -> bool {
        let _ = (agent, index);
        true
    }

    /// On the executor, before `agent` refines `batch`: true makes the
    /// refine fail, as the agent program would; a panic is the executor's.
    fn fail_refine(&self, agent: AgentId, batch: &Batch) -> bool {
        let _ = (agent, batch);
        false
    }

    /// Before the leader of `agent` dry-runs accumulate on `batch`'s
    /// result: true makes it fail, as a trap in accumulate would.
    fn fail_dry_run(&self, agent: AgentId, batch: &Batch) -> bool {
        let _ = (agent, batch);
        false
    }

    /// Before a replica applies `agent`'s work result `result` at `index`:
    /// true applies it as accumulate failing on it would, with no writes.
    /// A test must answer alike on every replica.
    fn fail_apply(&self, agent: AgentId, index: u64, result: &[u8]) -> bool {
        let _ = (agent, index, result);
        false
    }

    /// Before this node serves a peer a blob: false withholds it, as a
    /// node lacking it would.
    fn serve_blob(&self) -> bool {
        true
    }

    /// Before the storage thread commits: true makes the commit fail with
    /// nothing written, as fjall's first failure does (it then refuses
    /// every later commit, so the node stops).
    fn fail_commit(&self) -> bool {
        false
    }
}

/// No faults.
pub struct NoHooks;

impl Hooks for NoHooks {}
