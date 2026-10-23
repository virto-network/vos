//! The VOS node host: its storage and, on one process, every agent it
//! runs (`Node`).

mod anchor_keys;
pub mod blobs;

#[cfg(test)]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod asking;
mod calls;
pub mod client;
mod dispatch;
mod executor;
mod fault;
#[cfg(feature = "faults")]
pub mod faults;
mod group;
mod http;
mod ingress;
mod leader;
mod liveness;
mod messages;
mod node;
pub mod peer;
mod prover;
mod pvm;
mod queries;
pub mod raft;
pub mod roots;
mod signature;
mod space;
mod stats;
pub mod storage;
pub mod store;
pub mod tls;
mod workflows;

pub use anchor_keys::rotate_anchor_key;
pub use node::{
    ADMIN_TOKEN, CallError, Config, Error, NODE_KEY, Node, Peers, ReplaceError, Reply, STORE,
    wall_clock,
};
pub use space::{Space, SpaceNode, genesis_path, read_genesis, write_genesis};

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use smol::future::FutureExt;
use vos_wire::Encode;
use vos_wire::batch::Batch;
use vos_wire::ids::AgentId;
use vos_wire::peer::{CreationRecord, NodeNumber};

/// The identity of the agent `record` creates: its record's hash. Clients
/// sign for it, and its replica group is named by it.
pub fn identity(record: &CreationRecord) -> [u8; 32] {
    vos_pvm::precompile::blake2b_256(&record.encode())
}

/// `work`'s output, if it ends within `limit`.
pub(crate) async fn timeout<T>(limit: Duration, work: impl Future<Output = T>) -> Option<T> {
    let work = async { Some(work.await) };
    work.or(async {
        smol::Timer::after(limit).await;
        None
    })
    .await
}

/// `mutex`, locked. A lock a panic poisoned panics here too.
#[track_caller]
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().expect("unpoisoned")
}

/// 32 bytes from 64 hex digits, `None` for anything else. The text may
/// come off the wire, so it is sliced only where it has those bytes, and
/// each pair must be two hex digits, which a sign is not.
pub(crate) fn hex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (at, byte) in out.iter_mut().enumerate() {
        let pair = text.get(2 * at..2 * at + 2)?;
        if !pair.bytes().all(|digit| digit.is_ascii_hexdigit()) {
            return None;
        }
        *byte = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

/// `bytes` in lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Raise `key`'s value in `map` to `value`, if that is higher.
pub(crate) fn raise<K: Eq + Hash>(map: &mut HashMap<K, u64>, key: K, value: u64) {
    let raised = map.entry(key).or_insert(value);
    *raised = (*raised).max(value);
}

/// The wait before trying again what the node failed: [`Backoff::FIRST`]
/// at first, doubled at each try up to [`Backoff::MOST`].
pub(crate) struct Backoff(Duration);

impl Backoff {
    pub(crate) const FIRST: Duration = Duration::from_millis(50);
    const MOST: Duration = Duration::from_secs(5);

    /// The wait before this try, the next one's doubled.
    pub(crate) fn next(&mut self) -> Duration {
        let wait = self.0;
        self.0 = (wait * 2).min(Self::MOST);
        wait
    }

    /// Back to the first wait, once a try succeeded.
    pub(crate) fn reset(&mut self) {
        self.0 = Self::FIRST;
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self(Self::FIRST)
    }
}

/// Random bytes, from the operating system's randomness.
pub(crate) fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    getrandom::getrandom(&mut bytes).expect("the operating system's randomness");
    bytes
}

/// What a caught panic said.
pub(crate) fn panic_message(panic: &(dyn std::any::Any + Send)) -> String {
    panic
        .downcast_ref::<&str>()
        .map(|message| (*message).to_string())
        .or_else(|| panic.downcast_ref::<String>().cloned())
        .unwrap_or_default()
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

    /// As a request from node `to` for the blob `hash` arrives: false
    /// withholds it, as a node lacking it would.
    fn serve_blob(&self, to: NodeNumber, hash: &[u8; 32]) -> bool {
        let _ = (to, hash);
        true
    }

    /// Before a replica reads the blob holding `agent`'s work result at
    /// `index` to apply it: true reads it as missing, as a store that lost
    /// it would.
    fn lose_blob(&self, agent: AgentId, index: u64) -> bool {
        let _ = (agent, index);
        false
    }

    /// Before a leader first sends chunk `sequence` of a snapshot stream to
    /// `to`, whose follower has asked for the chunks from `wanted` on (0
    /// before it answered): how long it waits first, as on a slow link.
    fn delay_chunk(&self, to: NodeNumber, sequence: u64, wanted: u64) -> Duration {
        let _ = (to, sequence, wanted);
        Duration::ZERO
    }

    /// Whether `agent`'s leader reports its root at window `window`'s cut
    /// to the space's representative now: false holds the report, as a
    /// leader slow to send it would, until the hook says otherwise.
    fn report(&self, agent: AgentId, window: u64) -> bool {
        let _ = (agent, window);
        true
    }

    /// Before the representative's leader, its cut of `window` built and
    /// its anchor handed to the venue, proposes the window's close: false
    /// stops the leader there, as a crash would.
    fn close(&self, agent: AgentId, window: u64) -> bool {
        let _ = (agent, window);
        true
    }

    /// Before the storage thread commits: true makes the commit fail with
    /// nothing written, as fjall's first failure does (it then refuses
    /// every later commit, so the node stops).
    fn fail_commit(&self) -> bool {
        false
    }

    /// Before the storage thread syncs a commit it wrote: true makes the
    /// commit fail unsynced, as a failed fsync does. What it wrote may
    /// still reach the disk.
    fn fail_sync(&self) -> bool {
        false
    }
}

/// No faults.
pub struct NoHooks;

impl Hooks for NoHooks {}
