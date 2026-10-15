//! How a node runs, and how it answers.

use std::sync::Arc;
use std::time::Duration;

use vos_wire::defaults;

use super::wall_clock;
use crate::Hooks;
use crate::blobs::Horizons;
use crate::space::Space;
use crate::tls::IngressTls;

/// How a node reaches the other nodes of its space.
#[derive(Clone)]
pub enum Peers {
    /// QUIC, listening on this node's peer address in the space.
    Quic,
    /// A hub in this process, for tests.
    Hub(vos_net::memory::Hub),
}

/// How a node runs.
pub struct Config {
    /// The agent program every agent runs, as a standard program.
    pub agent: Vec<u8>,
    /// Executor threads for PVM work.
    pub executors: usize,
    /// Client requests an agent queues before a call answers busy.
    pub queue: usize,
    /// The most inputs in one batch.
    pub max_inputs: usize,
    /// The most argument bytes in one batch.
    pub max_bytes: usize,
    /// How long a leader waits for more inputs after the first, when it
    /// found its queue empty.
    pub linger: Duration,
    /// Refine's gas for one run: a query's, or a batch's budget, beyond
    /// which a refine has what decoding its batch may take.
    pub refine_gas: u64,
    /// Accumulate's gas for the agents this node creates: their creation
    /// records carry it to every replica.
    pub accumulate_gas: u64,
    /// Where a test breaks the node as a crash or a bug would.
    pub hooks: Arc<dyn Hooks>,
    /// The faults a test injects, read from a control file.
    #[cfg(feature = "faults")]
    pub faults: Option<Arc<crate::faults::Faults>>,
    /// Milliseconds since the Unix epoch: work-result time, and ingress's
    /// freshness checks. A test moves it.
    pub clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    /// TLS on the ingress. Without it, the ingress serves loopback
    /// addresses only.
    pub ingress_tls: Option<IngressTls>,
    /// The space this node runs in. Without one, it is a space of one, as
    /// node 0.
    pub space: Option<Space>,
    /// How the node reaches the other nodes of its space.
    pub peers: Peers,
    /// Where the peer endpoint binds, when not the address its space
    /// lists: behind port forwarding, a relay, or in a container.
    pub peer_bind: Option<std::net::SocketAddr>,
    /// How long a connection to a peer may stay quiet before it closes.
    pub quic_idle: Duration,
    /// A replica group's election timeout in milliseconds, drawn between
    /// these.
    pub election_timeout_ms: (u64, u64),
    /// How often a group's leader sends heartbeats, in milliseconds.
    pub heartbeat_ms: u64,
    /// How long a call or an admin command, once queued at the leader,
    /// waits for its answer before it answers that it may have run.
    pub answered: Duration,
    /// How long an agent's messages to another may stay unacknowledged
    /// before its leader sends them again, doubled each time that brings
    /// nothing, up to 16 times this. A receiver's `Behind` sends them
    /// again sooner.
    pub resend_round: Duration,
    /// A group's log is compacted once this many entries past its start
    /// are applied durably.
    pub compact_every: u64,
    /// A group's log is compacted once this many bytes of entries past its
    /// start are applied durably, an entry counting its payload and a large
    /// result's blob.
    pub compact_bytes: u64,
    /// The most entries a compaction keeps below the point it could
    /// compact to, for a follower a little behind.
    pub compact_tail: u64,
    /// The most bytes of entries a compaction keeps below that point,
    /// counted alike: well under `compact_bytes`, or every commit makes a
    /// compaction due. Counting large results' blobs, the default keeps
    /// about four to eight of them, and a follower further behind takes a
    /// snapshot.
    pub compact_tail_bytes: u64,
    /// How often the node collects its blob store.
    pub blob_collect_every: Duration,
    /// A blob goes once no log row names it, no pin holds it, and nobody
    /// put or touched it within this horizon: long enough for an install's
    /// entry to name the programs its leader alone holds.
    pub blob_horizon: Duration,
    /// The horizon of a blob a log row names from its first moments: a
    /// large work result, held from its put until its entry is written, or
    /// a blob fetched for an entry. A row keeps it from then on, so it goes
    /// at the first collection this long past its last put or touch once
    /// the log is compacted past the entry.
    pub named_blob_horizon: Duration,
    /// About how many bytes of rows one snapshot chunk carries.
    pub snapshot_chunk: usize,
    /// How long a leader waits for a follower to acknowledge a snapshot
    /// before it would send another: one still streaming goes on, and the
    /// leader starts another only once it ended.
    pub snapshot_timeout_ms: u64,
    /// How many owners' reads of workflows may wait at once at the node's
    /// ingress, each read again at every apply: one past them answers
    /// where its workflow stands at once. The node cannot tell a client
    /// that hung up mid-wait, whose read holds its place until its wait
    /// ends; the bound keeps what such reads cost small.
    pub workflow_waits: usize,
    /// The longest a read of a workflow waits for it to end: at most
    /// [`vos_wire::ingress::MAX_WORKFLOW_WAIT_MS`].
    pub workflow_wait: Duration,
    /// The most connections the ingress holds open at once: one past them
    /// is closed as it is accepted.
    pub ingress_connections: usize,
}

impl Config {
    pub fn new(agent: Vec<u8>) -> Self {
        Self {
            agent,
            executors: std::thread::available_parallelism()
                .map_or(1, |cores| cores.get().saturating_sub(1).max(1)),
            queue: 1024,
            max_inputs: 256,
            max_bytes: 1 << 20,
            linger: Duration::from_millis(2),
            refine_gas: defaults::REFINE_GAS,
            accumulate_gas: defaults::REFINE_GAS,
            hooks: Arc::new(crate::NoHooks),
            #[cfg(feature = "faults")]
            faults: None,
            clock: Arc::new(wall_clock),
            ingress_tls: None,
            space: None,
            peer_bind: None,
            quic_idle: vos_net::quic::IDLE,
            peers: Peers::Quic,
            election_timeout_ms: (1500, 3000),
            heartbeat_ms: 500,
            answered: Duration::from_secs(30),
            resend_round: Duration::from_secs(1),
            compact_every: 1024,
            compact_bytes: 64 << 20,
            blob_collect_every: Duration::from_secs(600),
            blob_horizon: Duration::from_secs(3_600),
            named_blob_horizon: Duration::from_secs(60),
            compact_tail: 256,
            compact_tail_bytes: 16 << 20,
            snapshot_chunk: 1 << 20,
            snapshot_timeout_ms: 60_000,
            workflow_waits: 64,
            workflow_wait: Duration::from_millis(vos_wire::ingress::MAX_WORKFLOW_WAIT_MS),
            ingress_connections: 1024,
        }
    }
}

/// The plain values of a node's [`Config`], as its parts read them.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Settings {
    /// Client requests, and messages from other agents, an agent queues
    /// before it answers busy: [`Config::queue`].
    pub(crate) queue_cap: usize,
    pub(crate) max_inputs: usize,
    pub(crate) max_bytes: usize,
    pub(crate) linger: Duration,
    pub(crate) refine_gas: u64,
    pub(crate) accumulate_gas: u64,
    pub(crate) election_timeout_ms: (u64, u64),
    pub(crate) answered: Duration,
    pub(crate) resend_round: Duration,
    pub(crate) heartbeat_ms: u64,
    pub(crate) compact_every: u64,
    pub(crate) compact_bytes: u64,
    pub(crate) compact_tail: u64,
    pub(crate) compact_tail_bytes: u64,
    pub(crate) blob_collect_every: Duration,
    pub(crate) blob_horizons: Horizons,
    pub(crate) snapshot_chunk: usize,
    pub(crate) snapshot_timeout_ms: u64,
    pub(crate) workflow_waits: usize,
    pub(crate) workflow_wait: Duration,
    pub(crate) ingress_connections: usize,
}

impl Settings {
    /// `config`'s values; a batch takes one input at least.
    pub(crate) fn of(config: &Config) -> Self {
        Self {
            queue_cap: config.queue,
            max_inputs: config.max_inputs.max(1),
            max_bytes: config.max_bytes,
            linger: config.linger,
            refine_gas: config.refine_gas,
            accumulate_gas: config.accumulate_gas,
            election_timeout_ms: config.election_timeout_ms,
            answered: config.answered,
            resend_round: config.resend_round,
            heartbeat_ms: config.heartbeat_ms,
            compact_every: config.compact_every,
            compact_bytes: config.compact_bytes,
            compact_tail: config.compact_tail,
            compact_tail_bytes: config.compact_tail_bytes,
            blob_collect_every: config.blob_collect_every,
            blob_horizons: Horizons {
                named: config.named_blob_horizon,
                aged: config.blob_horizon,
            },
            snapshot_chunk: config.snapshot_chunk,
            snapshot_timeout_ms: config.snapshot_timeout_ms,
            workflow_waits: config.workflow_waits,
            workflow_wait: config.workflow_wait.min(Duration::from_millis(
                vos_wire::ingress::MAX_WORKFLOW_WAIT_MS,
            )),
            ingress_connections: config.ingress_connections,
        }
    }
}
