//! The VOS node host: its storage and, on one process, every agent it
//! runs (`Node`).

pub mod blobs;
pub mod client;
mod executor;
pub mod http;
mod ingress;
mod node;
pub mod peer;
mod pvm;
pub mod raft;
pub mod storage;
pub mod store;

pub use ingress::SESSIONS_PER_KEY;
pub use node::{ADMIN_TOKEN, CallError, Config, Error, Node, Reply, wall_clock};

use vos_wire::batch::Batch;
use vos_wire::ids::AgentId;

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
