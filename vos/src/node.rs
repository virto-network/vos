//! Multi-agent node — runs multiple services on separate threads.
//!
//! Each agent/service gets its own [`VosRuntime`] on a dedicated thread.
//! All services on a node share a **global ID namespace** with a common
//! node prefix:
//!
//! ```text
//! ServiceId = [node_prefix: 16 bits][local_id: 16 bits]
//! ```
//!
//! Cross-agent transfers are routed by the node: if the target's prefix
//! matches this node, the message is delivered locally. Otherwise it's
//! forwarded to the network layer (future).

use std::collections::HashMap;
// HashSet is only used by the CRDT/Raft sync+replication paths (peer-set
// and sync-head dedup), which need both features; OnceLock backs the
// network-only manifest slot. Gating each to exactly the features its
// users require keeps every reduced-feature build warning-clean.
#[cfg(all(feature = "storage", feature = "network"))]
use std::collections::HashSet;
#[cfg(feature = "network")]
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex, RwLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use tracing::{debug, error, info, warn};

use crate::abi::service::ServiceId;
use crate::runtime::VosRuntime;

/// A message routed between agents via the node.
#[derive(Debug, Clone)]
pub struct Envelope {
    pub from: ServiceId,
    pub to: ServiceId,
    pub payload: Vec<u8>,
}

/// Handle to a running agent thread.
struct AgentHandle {
    join: Option<thread::JoinHandle<AgentResult>>,
}

/// Result returned when an agent thread completes.
///
/// `panics` counts PVM-side panics during refine. `error` is set
/// when the host itself failed unrecoverably — strategy build,
/// replay rebuild divergence, commit failure — and we tore the
/// agent down rather than continuing with corrupt state.
pub struct AgentResult {
    pub id: ServiceId,
    pub panics: u32,
    pub error: Option<String>,
}

impl AgentResult {
    /// Did the agent finish cleanly (no PVM panics, no host errors)?
    pub fn is_ok(&self) -> bool {
        self.panics == 0 && self.error.is_none()
    }
}

/// Replication / persistence semantics selected per agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Consistency {
    /// In-memory only — state is lost when the agent exits. The
    /// default; matches the pre-persistence behaviour.
    #[default]
    Ephemeral,
    /// redb-backed local persistence (no replication, no log).
    Local,
    /// Merkle-CRDT replication: state + DAG + roots are written
    /// atomically on every dispatch, and the observed-effect log
    /// is attached to each DAG node for deterministic replay.
    Crdt,
    /// Raft consensus — every state-changing dispatch appends a
    /// committed log entry. Single-node mode runs as a "self-quorum"
    /// (durable persistence + replay equivalent to `Local` + a log);
    /// cluster machinery (election, AppendEntries,
    /// leader-forwarding `commit_with_log`) activates when peers join.
    Raft,
}

impl Consistency {
    /// Byte encoding, matching the registry `AgentRow.consistency`
    /// wire order (`Ephemeral`=0, `Local`=1, `Crdt`=2, `Raft`=3).
    pub(crate) fn as_u8(self) -> u8 {
        self as u8
    }

    /// Inverse of [`Self::as_u8`]; `None` for an unknown byte.
    pub(crate) fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Ephemeral),
            1 => Some(Self::Local),
            2 => Some(Self::Crdt),
            3 => Some(Self::Raft),
            _ => None,
        }
    }

    /// Position on the monotone *shareability* lattice — higher means
    /// more widely shared. Confined tiers (`Ephemeral`, `Local`) keep
    /// state on this node; `Crdt`/`Raft` both replicate it off-node and
    /// are rank-equal (distinguished only by algorithm). An installed
    /// agent's shareability may only ever *decrease*: a `Local` keystore
    /// can never be widened into replication. See [`VosNode::seal_consistency`].
    pub(crate) fn shareability(self) -> u8 {
        match self {
            Self::Ephemeral => 0,
            Self::Local => 1,
            Self::Crdt | Self::Raft => 2,
        }
    }

    /// `true` for the node-confined tiers (`Ephemeral`, `Local`) whose
    /// state never leaves this device. Such an agent — the messenger's
    /// MLS keys, CSPRNG seed and decrypted plaintext are the load-bearing
    /// example — must be reachable only from in-process host calls, never
    /// from a remote peer's `InvokeRequest`. The replicated tiers
    /// (`Crdt`/`Raft`) are the only ones that legitimately answer the
    /// network. See [`NodeService::dispatch_invoke`].
    pub(crate) fn is_node_confined(self) -> bool {
        self.shareability() < Self::Crdt.shareability()
    }
}

/// The effective consistency once the monotone locality seal is applied: a
/// persisted `sealed` floor pins the tier this instance was first spawned at,
/// so a forged or merged registry row can't change it. Honoured: an exact
/// re-spawn, or a deliberate *narrowing* (lower shareability — more confined).
/// Pinned back to `sealed`: a shareability *widening* (e.g. `Local`→`Crdt`),
/// AND a `Crdt`↔`Raft` *lateral* — same shareability, but it swaps the
/// replication trust model (consensus-sequenced Raft ↔ merge-anyone CRDT), so
/// a forged catalog byte must not be able to downgrade a Raft replica to CRDT
/// The earlier seal collapsed `Crdt`/`Raft` to one shareability rank and
/// let the lateral through; this pins the exact tier instead.
#[cfg(feature = "storage")]
pub(crate) fn effective_after_seal(
    sealed: Option<Consistency>,
    requested: Consistency,
) -> Consistency {
    match sealed {
        Some(s) if requested == s => requested,
        Some(s) if requested.shareability() < s.shareability() => requested,
        Some(s) => s,
        None => requested,
    }
}

/// Configuration for registering an agent in the node.
pub struct AgentConfig {
    /// PVM blob (already transpiled).
    pub blob: Vec<u8>,
    /// Installed instance name, recorded in the node's [`AgentNames`]
    /// reverse map at register time so the auth path can resolve this
    /// agent's `ServiceId` back to a name (actor-local grant probes,
    /// `intra_caps` targets). `None` for anonymous/test agents — the
    /// reverse map simply gets no row, and name-keyed auth lookups fall
    /// back to deny (the prior behaviour for every non-registry target).
    pub name: Option<String>,
    /// Initial payloads to deliver on startup.
    pub init_payloads: Vec<Vec<u8>>,
    /// Pre-populated storage entries (key, value).
    pub storage: Vec<(Vec<u8>, Vec<u8>)>,
    /// Optional data directory for state persistence. When set and
    /// `consistency` isn't `Ephemeral`, the agent's redb file is
    /// created at `{data_dir}/agents/{svc_id}.redb`.
    pub data_dir: Option<std::path::PathBuf>,
    /// Replication / persistence semantics for this agent.
    pub consistency: Consistency,
    /// Opt a node-confined (`Local`/`Ephemeral`) agent OUT of the
    /// device-private network gate, so remote peers may invoke it. The
    /// gate exists for agents whose single-node state is device-private
    /// (the messenger's MLS keys, CSPRNG seed, decrypted plaintext) and
    /// must never leave the device — those stay confined (the default,
    /// `false`). But a single-node agent can also be authoritative state
    /// deliberately served over the network — a per-node authoritative store
    /// answering remote reads, a stateless forwarding bridge — and those set
    /// this so the confinement gate lets peer invokes through. No effect on
    /// `Crdt`/`Raft` agents (never confined) — see
    /// [`Consistency::is_node_confined`] and [`NodeService::dispatch_invoke`].
    pub network_reachable: bool,
    /// 32-byte handle that identifies the *replication group* this
    /// agent belongs to. Replicas of the same logical actor on
    /// different nodes share this id and use it to find each other
    /// over the network. Only meaningful when `consistency ==
    /// Crdt`. `None` means "this CRDT actor has no peers" — its
    /// DAG stays purely local.
    pub replication_id: Option<[u8; 32]>,
    /// Pre-opened, shared `redb::Database` for the agent's
    /// `CrdtCommit`. When `register` plans to wire this actor
    /// into the network's `SyncHandler`, it opens the file
    /// here, hands the same `Arc` to the agent's commit
    /// strategy *and* to the sync layer — redb is exclusive on
    /// file open, so this is the only way to share. `None`
    /// means the agent thread opens the file itself.
    #[cfg(feature = "storage")]
    #[doc(hidden)]
    pub pre_opened_db: Option<Arc<redb::Database>>,
    /// Companion to `pre_opened_db`: the commit lock that
    /// serializes the agent thread's `commit_with_log` against
    /// the sync ticker's `insert_node` + `compact_roots`. Both
    /// must hand it to their `CrdtCommit::from_db_arc_locked`
    /// for the serialization to actually happen.
    #[cfg(feature = "storage")]
    #[doc(hidden)]
    pub pre_opened_lock: Option<Arc<Mutex<()>>>,
    /// Static cluster membership (list of `node_prefix`es) for
    /// `Consistency::Raft`. Empty = single-node degenerate mode.
    /// All cluster members must list the same set in the same
    /// order.
    pub members: Vec<u16>,
    /// Periodic `tick()` interval in milliseconds. When `Some(>0)`, the
    /// agent thread dispatches a synthetic `tick` message to the actor's
    /// `tick` handler about every interval, *between* inbound work — the
    /// same heartbeat the `.so` extension gets via its `tick_ms`. `None`
    /// (default) → no ticking. Only set this on agents that define a
    /// `tick` handler. Best-effort cadence: a long invoke delays the next
    /// tick (the thread never preempts a handler).
    pub tick_ms: Option<u64>,
    /// Declared intra-system capabilities — the ceiling [`SpaceRole`] this
    /// agent may relay to each named target on its OUTBOUND invokes. Empty
    /// (the default) keeps the legacy behaviour: an agent's outbound calls
    /// arrive as the trusted [`Caller::Actor`], which bypasses role gates —
    /// every existing agent→agent call relies on this. A NON-empty list
    /// opts this agent into bounded relay instead: it relays the real
    /// caller's role capped by these caps (the same model as an extension's
    /// `intra_caps`), so a privileged downstream call needs a
    /// correspondingly-privileged original caller. See [`IntraCap`].
    pub intra_caps: Vec<crate::actors::IntraCap>,
    /// Pre-spawned Raft worker for `Consistency::Raft` multi-mode
    /// replication. `register` spawns this when the right
    /// conditions hold (multi-member + network attached + storage
    /// feature on) and hands it to the agent thread, which builds
    /// `RaftCommit::from_worker` with it. Caller code shouldn't
    /// set this directly.
    #[cfg(all(feature = "storage", feature = "network"))]
    #[doc(hidden)]
    pub raft_worker: Option<crate::raft::RaftWorker>,
    /// Apply-receiver paired with `raft_worker`. Drained by
    /// `RaftCommit::commit_with_log` while waiting for an
    /// in-flight propose to commit.
    #[cfg(all(feature = "storage", feature = "network"))]
    #[doc(hidden)]
    pub raft_apply_rx: Option<std::sync::mpsc::Receiver<u64>>,
    /// Per-replica gate on peer-merged CRDT nodes (see
    /// [`NodeValidator`](crate::commit::NodeValidator)). Installed on the
    /// space-registry replica to bind the genesis `set_root` to the
    /// advertised space_id; `None` (default) accepts all peer nodes.
    #[cfg(feature = "storage")]
    pub node_validator: Option<crate::commit::NodeValidator>,
}

impl AgentConfig {
    /// Build a config with no persistence (the default).
    pub fn new(blob: Vec<u8>) -> Self {
        Self {
            blob,
            name: None,
            init_payloads: Vec::new(),
            storage: Vec::new(),
            data_dir: None,
            consistency: Consistency::Ephemeral,
            network_reachable: false,
            replication_id: None,
            #[cfg(feature = "storage")]
            pre_opened_db: None,
            #[cfg(feature = "storage")]
            pre_opened_lock: None,
            members: Vec::new(),
            tick_ms: None,
            intra_caps: Vec::new(),
            #[cfg(all(feature = "storage", feature = "network"))]
            raft_worker: None,
            #[cfg(all(feature = "storage", feature = "network"))]
            raft_apply_rx: None,
            #[cfg(feature = "storage")]
            node_validator: None,
        }
    }

    /// Set the static cluster membership for `Consistency::Raft`
    /// — list of `node_prefix`es. Same list on every replica.
    pub fn with_members(mut self, members: Vec<u16>) -> Self {
        self.members = members;
        self
    }

    /// Dispatch a synthetic `tick` to this agent's `tick` handler about
    /// every `ms` milliseconds (0 disables). Only meaningful for agents
    /// that define a `tick` handler.
    pub fn with_tick_ms(mut self, ms: u64) -> Self {
        self.tick_ms = (ms > 0).then_some(ms);
        self
    }

    /// Opt this agent into bounded caller-relay on its outbound invokes —
    /// the ceiling [`SpaceRole`] it may relay to each named target. Empty
    /// (the default) keeps the legacy trusted [`Caller::Actor`] relay. See
    /// [`IntraCap`].
    pub fn with_intra_caps(mut self, caps: Vec<crate::actors::IntraCap>) -> Self {
        self.intra_caps = caps;
        self
    }

    /// Attach initial payloads dispatched on cold start.
    pub fn with_init_payloads(mut self, payloads: Vec<Vec<u8>>) -> Self {
        self.init_payloads = payloads;
        self
    }

    /// Record the agent's installed instance name so the node's
    /// [`AgentNames`] reverse map can resolve its `ServiceId` back to a
    /// name for the auth path. Set by `vosx` from the manifest/registry
    /// at install time; left unset for anonymous test agents.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Attach pre-populated storage (key, value) entries.
    pub fn with_storage(mut self, storage: Vec<(Vec<u8>, Vec<u8>)>) -> Self {
        self.storage = storage;
        self
    }

    /// Pick the replication/persistence strategy.
    pub fn with_consistency(mut self, c: Consistency) -> Self {
        self.consistency = c;
        self
    }

    /// Let remote peers invoke this node-confined (`Local`/`Ephemeral`)
    /// agent — for single-node state that is authoritative-but-network-
    /// served (a per-node authoritative store, a forwarding bridge) rather
    /// than device-private. Leaves device-private agents (the messenger)
    /// confined by default. See [`AgentConfig::network_reachable`].
    pub fn network_reachable(mut self) -> Self {
        self.network_reachable = true;
        self
    }

    /// Enable persistence under the given data directory.
    pub fn persist(mut self, data_dir: impl Into<std::path::PathBuf>) -> Self {
        self.data_dir = Some(data_dir.into());
        self
    }

    /// Pin this agent into a named replication group. Replicas
    /// across nodes that share the same id automatically discover
    /// each other (over an attached `Network`) and converge their
    /// merkle-DAGs.
    pub fn with_replication_id(mut self, id: [u8; 32]) -> Self {
        self.replication_id = Some(id);
        self
    }

    /// Gate peer-merged CRDT nodes through `validator` (see
    /// [`NodeValidator`](crate::commit::NodeValidator)). The daemon sets
    /// this on the space-registry replica to reject a forged genesis
    /// whose CID doesn't derive the advertised space_id.
    #[cfg(feature = "storage")]
    pub fn with_node_validator(mut self, validator: crate::commit::NodeValidator) -> Self {
        self.node_validator = Some(validator);
        self
    }

    /// Convenience: derive a replication id from the agent's blob
    /// plus a logical name. Replicas with identical (blob, name)
    /// automatically share an id without manifest coordination.
    pub fn auto_replication_id(mut self, name: &str) -> Self {
        let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
        h.update(name.as_bytes());
        h.update(&[0u8]); // delimiter so name||blob ≠ shifted variants
        h.update(&self.blob);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        self.replication_id = Some(out);
        self
    }

    /// Derive the redb path for this agent from its data directory
    /// and service ID. Only meaningful when the `storage` feature
    /// is enabled.
    #[cfg(feature = "storage")]
    fn db_path(&self, id: ServiceId) -> Option<std::path::PathBuf> {
        let data_dir = self.data_dir.as_ref()?;
        let dir = data_dir.join("agents");
        std::fs::create_dir_all(&dir).ok()?;
        Some(dir.join(format!("{:08x}.redb", id.0)))
    }

    /// Node-local sidecar recording the narrowest consistency tier this
    /// instance was ever spawned at — the monotone locality seal. Sits
    /// next to the agent's redb so it shares the agent's lifetime.
    #[cfg(feature = "storage")]
    fn seal_path(&self, id: ServiceId) -> Option<std::path::PathBuf> {
        let dir = self.data_dir.as_ref()?.join("agents");
        std::fs::create_dir_all(&dir).ok()?;
        Some(dir.join(format!("{:08x}.seal", id.0)))
    }

    /// Enforce the monotone locality seal on this config's requested
    /// consistency. Best-effort and node-local: with no `data_dir` or no
    /// `name` there is nothing durable to seal, so the request passes
    /// through. Otherwise the (possibly narrowed) tier is persisted, so a
    /// later spawn — even one driven by a forged or CRDT-merged registry
    /// row — can never *widen* a sealed agent's shareability. This is the
    /// load-bearing half of immutable-local: the registry is replicated
    /// and not trusted, so the seal lives here on the host, ahead of the
    /// sync-attach branches that key on `config.consistency`.
    #[cfg(feature = "storage")]
    fn apply_consistency_seal(&mut self, id: ServiceId) {
        if self.name.is_none() {
            return;
        }
        let Some(path) = self.seal_path(id) else {
            return;
        };
        let sealed = std::fs::read(&path)
            .ok()
            .and_then(|b| b.first().copied())
            .and_then(Consistency::from_u8);
        let effective = effective_after_seal(sealed, self.consistency);
        if effective != self.consistency {
            warn!(
                %id,
                requested = ?self.consistency,
                sealed = ?sealed,
                effective = ?effective,
                "consistency: refusing to widen a sealed agent; pinning to the sealed tier",
            );
        }
        let _ = std::fs::write(&path, [effective.as_u8()]);
        self.consistency = effective;
    }
}

/// Configuration for registering a native extension in the node.
pub struct ExtensionConfig {
    /// Path to the extension `.so` file.
    pub path: std::path::PathBuf,
    /// Installed instance name, recorded in the node's [`AgentNames`]
    /// reverse map at register time. Mirrors [`AgentConfig::name`] for
    /// the extension side — lets an extension be the *target* of a
    /// named `intra_cap` and of actor-local grants. `None` for
    /// anonymous/test extensions.
    pub name: Option<String>,
    /// rkyv-encoded `vos::value::Args` for the extension's constructor.
    /// Empty if the constructor takes no parameters.
    pub init_args: Vec<u8>,
    /// Optional data directory for state persistence.
    /// When set, the extension's redb file is created at
    /// `{data_dir}/extensions/{name}.redb`.
    pub data_dir: Option<std::path::PathBuf>,
    /// Sprint 2: cap-overage policy applied at the host ABI
    /// boundary for this extension. Default `Block` — refuse
    /// syscalls outside the declared caps. Override via the space
    /// manifest's `cap_policy = "log"`/`"block"`/`"kill"`.
    pub cap_policy: crate::extension::CapPolicy,
    /// M9 — relay-only mode for extensions that proxy external
    /// traffic (the HTTP gateway). When `true`, the host's
    /// invoke closure tags every outbound call from this
    /// extension as [`Caller::Unauthenticated`] instead of the
    /// default [`Caller::Actor`] intra-system bypass. Default
    /// `false` for traditional extensions that compose with
    /// other actors as trusted in-process peers.
    ///
    /// Deprecated synonym for `intra_caps = []`: now that the
    /// default *denies* (an extension with no declared caps relays
    /// every outbound call as [`Caller::Unauthenticated`]), this
    /// flag is redundant. Kept for back-compat with existing
    /// gateway manifests. When `true`, [`Self::relay_unauthenticated`]
    /// also clears `intra_caps` so the "relay has no authority"
    /// guarantee can't be accidentally combined with a declared cap.
    pub relay_unauthenticated: bool,
    /// Declared intra-system capabilities — the ceiling [`SpaceRole`]
    /// this extension may relay to each named target actor. Empty
    /// (the default) means the extension has *no* authority to relay:
    /// every outbound call arrives [`Caller::Unauthenticated`], so
    /// role-gated handlers refuse it. See [`IntraCap`] for the
    /// intersection model and wildcard semantics.
    pub intra_caps: Vec<crate::actors::IntraCap>,
    /// PEM-encoded server certificate chain for host-terminated
    /// TLS on this extension's byte-stream listeners. When both this and
    /// [`Self::tls_key_pem`] are set, the host builds a TLS acceptor and a
    /// `ctx.listen_tls(addr)` listener wraps every accepted connection so
    /// the extension reads/writes plaintext. `None` → `listen_tls` fails
    /// (no cert configured). Operator-supplied (manifest / secret file).
    pub tls_cert_pem: Option<Vec<u8>>,
    /// PEM-encoded private key paired with [`Self::tls_cert_pem`].
    pub tls_key_pem: Option<Vec<u8>>,
    /// The address the host binds a
    /// listener on for a `kind = Transport` extension (one declaring
    /// `handle_connection`). `None` for actor/service extensions. The
    /// host owns the accept loop and spawns one concurrent `&self`
    /// connection task per accept. When [`Self::serves_tls`] is set the
    /// host terminates TLS on each accepted connection (so the extension
    /// reads/writes plaintext), which additionally requires
    /// [`Self::tls_cert_pem`]/[`Self::tls_key_pem`].
    pub serves_addr: Option<String>,
    /// Whether the transport listener terminates TLS host-side.
    pub serves_tls: bool,
    /// Backpressure cap: the maximum number of connection tasks the
    /// transport driver runs concurrently. At the cap the accept loop
    /// refuses new connections (accept-then-close) rather than spawning
    /// unboundedly. Defaults to [`DEFAULT_TRANSPORT_MAX_CONNS`].
    pub serves_max_conns: usize,
    /// Periodic `tick()` interval, in milliseconds. When
    /// `Some`, the actor-mode driver dispatches a synthetic `tick` message
    /// (routed to the extension's `#[msg] async fn tick(&mut self, ctx)`
    /// handler) roughly every `tick_ms`, between inbound invokes/messages —
    /// how an actor-mode extension originates periodic work (e.g. a
    /// heartbeat ping) without a self-spun loop. `None` (default) →
    /// no ticking. Best-effort: a long-running invoke legitimately delays
    /// the next tick (the driver never preempts a handler).
    pub tick_ms: Option<u64>,
}

/// Default backpressure cap for a transport-mode extension's accept loop
/// (max concurrent connection tasks). Overridable via
/// [`ExtensionConfig::serves_max`].
pub const DEFAULT_TRANSPORT_MAX_CONNS: usize = 1024;

impl ExtensionConfig {
    /// Build a config with no init args and no persistence.
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: path.into(),
            name: None,
            init_args: Vec::new(),
            data_dir: None,
            cap_policy: crate::extension::CapPolicy::default(),
            relay_unauthenticated: false,
            intra_caps: Vec::new(),
            tls_cert_pem: None,
            tls_key_pem: None,
            serves_addr: None,
            serves_tls: false,
            serves_max_conns: DEFAULT_TRANSPORT_MAX_CONNS,
            tick_ms: None,
        }
    }

    /// Build a config with rkyv-encoded init args.
    pub fn with_args(path: impl Into<std::path::PathBuf>, args: &crate::value::Args) -> Self {
        let bytes = crate::rkyv::to_bytes::<crate::rkyv::rancor::Error>(args)
            .expect("rkyv encode Args")
            .to_vec();
        Self {
            path: path.into(),
            name: None,
            init_args: bytes,
            data_dir: None,
            cap_policy: crate::extension::CapPolicy::default(),
            relay_unauthenticated: false,
            intra_caps: Vec::new(),
            tls_cert_pem: None,
            tls_key_pem: None,
            serves_addr: None,
            serves_tls: false,
            serves_max_conns: DEFAULT_TRANSPORT_MAX_CONNS,
            tick_ms: None,
        }
    }

    /// Set the periodic [`tick`](Self::tick_ms) interval in milliseconds.
    /// The actor-mode driver then dispatches a synthetic `tick` message to
    /// the extension's `tick` handler roughly every `ms` between inbound
    /// work. Zero is treated as "no ticking" (same as `None`).
    pub fn with_tick_ms(mut self, ms: u64) -> Self {
        self.tick_ms = (ms > 0).then_some(ms);
        self
    }

    /// Configure a transport-mode extension's listen endpoint.
    /// The host binds `addr`, owns the accept loop, and spawns
    /// one concurrent `&self` connection task per accept against the
    /// extension's `handle_connection`. With `tls = true` the host
    /// terminates TLS on each connection (the extension sees plaintext),
    /// which also requires [`Self::tls_pem`].
    pub fn serves(mut self, addr: impl Into<String>, tls: bool) -> Self {
        self.serves_addr = Some(addr.into());
        self.serves_tls = tls;
        self
    }

    /// Override the transport backpressure cap (max concurrent connection
    /// tasks). A value of `0` is treated as [`DEFAULT_TRANSPORT_MAX_CONNS`].
    pub fn serves_max(mut self, max_conns: usize) -> Self {
        self.serves_max_conns = if max_conns == 0 {
            DEFAULT_TRANSPORT_MAX_CONNS
        } else {
            max_conns
        };
        self
    }

    /// Configure host-terminated TLS for this extension's `listen_tls`
    /// byte-stream listeners with a PEM cert chain + private key.
    pub fn tls_pem(mut self, cert_pem: impl Into<Vec<u8>>, key_pem: impl Into<Vec<u8>>) -> Self {
        self.tls_cert_pem = Some(cert_pem.into());
        self.tls_key_pem = Some(key_pem.into());
        self
    }

    /// Record the extension's installed instance name so the node's
    /// [`AgentNames`] reverse map can resolve its `ServiceId` back to a
    /// name. Set by `vosx` from the manifest; left unset for test
    /// extensions.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Mark the extension as a relay for external traffic — its
    /// outbound calls tag every InvokeRequest as
    /// [`Caller::Unauthenticated`] so the targeted actor's
    /// role-gated handlers can refuse anonymous HTTP / REST /
    /// future-gateway-protocol traffic. The HTTP gateway sets
    /// this; most other extensions leave it at the default
    /// `false` so they retain intra-system trust.
    pub fn relay_unauthenticated(mut self) -> Self {
        self.relay_unauthenticated = true;
        // Mutually exclusive with declared caps: a relay has no
        // authority of its own. Clearing here keeps the invariant
        // even if a manifest sets both shapes.
        self.intra_caps.clear();
        self
    }

    /// Declare the extension's intra-system capabilities — the
    /// ceiling [`SpaceRole`] it may relay to each named target.
    /// Ignored (cleared) when [`Self::relay_unauthenticated`] is
    /// also set, since a relay has no authority. See [`IntraCap`].
    pub fn with_intra_caps(mut self, caps: Vec<crate::actors::IntraCap>) -> Self {
        if self.relay_unauthenticated {
            return self;
        }
        self.intra_caps = caps;
        self
    }

    /// Enable state persistence under the given data directory.
    /// The extension's state is stored in `{data_dir}/extensions/{name}.redb`
    /// where `name` is derived from the `.so` filename.
    pub fn persist(mut self, data_dir: impl Into<std::path::PathBuf>) -> Self {
        self.data_dir = Some(data_dir.into());
        self
    }

    /// Override the cap-overage policy. Defaults to
    /// [`CapPolicy::Block`](crate::extension::CapPolicy::Block) —
    /// callers in tests that want the Sprint-1 warn-only
    /// behaviour pass `CapPolicy::Log`.
    pub fn with_cap_policy(mut self, policy: crate::extension::CapPolicy) -> Self {
        self.cap_policy = policy;
        self
    }

    /// Derive the redb path from the data directory and the .so filename.
    #[cfg(feature = "storage")]
    fn db_path(&self) -> Option<std::path::PathBuf> {
        let data_dir = self.data_dir.as_ref()?;
        let name = self
            .path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("extension")
            .trim_start_matches("lib");
        let dir = data_dir.join("extensions");
        std::fs::create_dir_all(&dir).ok()?;
        Some(dir.join(format!("{name}.redb")))
    }
}

/// Synchronous invoke request routed through `invoke_routes`.
///
/// `chain` carries the ServiceIds of the agents already on the
/// stack of synchronous invokes leading to this hop, including the
/// caller. Each agent's `external_invoke` checks the chain before
/// forwarding so an A→B→A cycle aborts immediately at the second
/// hop instead of deadlocking until the 10 s reply timeout. The
/// chain doubles as a depth counter — capped at
/// [`MAX_CROSS_AGENT_DEPTH`] hops.
struct InvokeRequest {
    /// Who's calling — host-side identity as seen by the dispatch
    /// gate. `Caller::Peer` for libp2p inbound (multihash bytes of
    /// the noise-verified PeerId); `Caller::Actor` for intra-system
    /// invokes (the calling actor's ServiceId); `Caller::Unauthenticated`
    /// for host-initiated calls and future HTTP gateway routes.
    #[allow(dead_code)] // Consumer wired via macro emission in M6.
    caller: crate::actors::Caller,
    /// Space-wide role byte for `caller`, decoded as a
    /// [`SpaceRole`](crate::actors::SpaceRole) discriminant.
    /// `None` for callers without a space-level grant (Unauthenticated
    /// or unknown peers). Populated by [`NodeService::dispatch_invoke`]
    /// in M5; until then, all sites leave it at `None`.
    #[allow(dead_code)] // Consumer wired in M3/M5.
    space_role: Option<u8>,
    /// Actor-local role byte for `caller`, decoded against the
    /// target actor's [`Role`](crate::Actor::Role) discriminant.
    /// `None` when no actor-local grant exists; falls back to the
    /// space-level grant mapped via `SPACE_ROLE_MAP`. Populated
    /// in M5; until then, all sites leave it at `None`.
    #[allow(dead_code)] // Consumer wired in M3/M5.
    actor_local_role: Option<u8>,
    msg: Vec<u8>,
    reply: ReplyChannel,
    // Read by agent_thread via `&req.chain` before moving `req`
    // into handle_invoke_request; rustc's read analysis misses
    // that pattern when the rest of the struct is then consumed.
    #[allow(dead_code)]
    chain: Vec<u32>,
}

/// The reply sink of an [`InvokeRequest`]. `Sync` (std mpsc) is the default for
/// every caller (actor/service/registry/libp2p replies) — its receiver is
/// awaited with a blocking `recv_timeout`. `Async` (a `futures_channel::oneshot`) lets a
/// Transport-mode connection task await its reply *on the
/// cooperative executor* — no blocking-pool thread, correlated per-call — so
/// many concurrent connections keep serving while one waits for its `ctx.ask`.
enum ReplyChannel {
    Sync(mpsc::Sender<Vec<u8>>),
    Async(futures_channel::oneshot::Sender<Vec<u8>>),
}

impl ReplyChannel {
    /// Deliver `reply` to the waiting caller. Single-use for `Async` (a
    /// `oneshot` consumes its sender). A closed/canceled receiver — the caller
    /// already timed out or gave up — is ignored, never panics.
    fn send(self, reply: Vec<u8>) {
        match self {
            ReplyChannel::Sync(tx) => {
                let _ = tx.send(reply);
            }
            ReplyChannel::Async(tx) => {
                let _ = tx.send(reply);
            }
        }
    }
}

/// Maximum number of cross-agent invoke hops in one synchronous
/// chain. Each agent's external_invoke aborts forwarding when
/// `chain.len()` reaches this. Picked generously — typical chains
/// are 1–3 deep; 32 catches runaway recursion without limiting
/// realistic compositions.
const MAX_CROSS_AGENT_DEPTH: usize = 32;

/// Maximum size, in bytes, of a single reply sent through an
/// `InvokeRequest`'s `reply_tx`. Distinct from the per-call
/// recording cap (`DEFAULT_REPLY_CAP`, 16 KiB) which bounds DAG
/// log size. The producer cap is much larger — it's a guardrail
/// against runaway memory pressure when an agent or worker
/// produces a multi-megabyte reply, not a consensus-history
/// concern. Replies exceeding this are dropped at the producer
/// side and surface as `InvokeError::NotFound` at the caller.
///
/// 8 MiB accommodates STARK proof bodies (the prover extension's
/// `prove` returns ~1.4 MiB; future production-config
/// proofs may exceed 2 MiB) without admitting unboundedly large
/// replies.
const MAX_PRODUCER_REPLY: usize = 8 * 1024 * 1024;

/// Send `reply` through `reply_tx` if it's within the producer
/// cap; otherwise log and drop the channel so the caller gets a
/// disconnect-shaped failure. Pulled out to share between
/// `handle_invoke_request` and `extension_thread`.
fn send_reply_capped(reply: ReplyChannel, bytes: Vec<u8>, svc_id: ServiceId) {
    if bytes.len() > MAX_PRODUCER_REPLY {
        warn!(
            %svc_id,
            size = bytes.len(),
            cap = MAX_PRODUCER_REPLY,
            "reply exceeds producer-side cap; dropping channel",
        );
        drop(reply); // disconnect (Sync) / cancel (Async) → caller sees failure
    } else {
        reply.send(bytes);
    }
}

/// Result of the pre-forward safety check on a synchronous invoke.
#[derive(Debug, PartialEq, Eq)]
enum InvokeForwardCheck {
    Allowed,
    /// Target is already in the chain — forwarding would form a
    /// cycle (and deadlock until the 10 s reply timeout).
    Cycle,
    /// Chain has reached the depth cap.
    DepthExceeded,
}

/// Decide whether to forward an invoke to `target` given the
/// caller's current chain. Pulled out as a free function so the
/// rule is testable without spinning up agent threads.
fn check_invoke_forward(chain: &[u32], target: u32) -> InvokeForwardCheck {
    if chain.contains(&target) {
        InvokeForwardCheck::Cycle
    } else if chain.len() >= MAX_CROSS_AGENT_DEPTH {
        InvokeForwardCheck::DepthExceeded
    } else {
        InvokeForwardCheck::Allowed
    }
}

/// A multi-agent VOS node.
///
/// Each agent runs on its own thread with its own `VosRuntime`.
/// All services share a global ID namespace scoped by `node_prefix`.
pub struct VosNode {
    node_prefix: u16,
    next_local: AtomicU16,
    /// Map from ServiceId → agent channel. Multiple services can map
    /// to the same agent (an agent with child actors).
    routes: HashMap<u32, mpsc::Sender<Envelope>>,
    agents: Vec<AgentHandle>,
    /// Outbound channel — agent threads send cross-service transfers here.
    outbox_tx: mpsc::Sender<Envelope>,
    outbox_rx: mpsc::Receiver<Envelope>,
    /// Map from ServiceId → synchronous invoke channel. Both
    /// workers and PVM agents register here. Wrapped in an
    /// `Arc<Mutex<...>>` so threads spawned earlier can resolve
    /// peers registered later — the alternative (cloning the map
    /// at thread spawn time) freezes A's view of the world before
    /// B exists, breaking cross-agent invoke order-independent.
    invoke_routes: InvokeRoutes,
    /// Reverse map `local_id → instance name`, populated at register
    /// time and read live by the auth path (the libp2p gate's
    /// actor-local probe and extension relays). Shared (cheap clone)
    /// into [`NodeService`] and into each service-extension thread.
    /// See [`AgentNames`].
    agent_names: AgentNames,
    /// Set by [`VosNode::run_until_idle`] (or `collect`) when the
    /// node decides it's done. Threads poll this at the top of
    /// their main loop and exit cleanly. Replaces the per-agent
    /// "exit after N seconds idle" heuristic with explicit
    /// node-driven lifecycle.
    ///
    /// NOTE: agent threads do NOT poll this directly — they each poll their
    /// own [`Self::agent_shutdown`] flag (which a node-wide shutdown fans out
    /// to via [`Self::signal_node_shutdown`]). This field is still the
    /// node-wide signal for non-agent machinery (network bridge, sync ticker,
    /// `InvokeHandle::is_shutting_down`).
    shutdown: Arc<AtomicBool>,
    /// Per-agent shutdown flags (`local_id → flag`), allocated at
    /// register time. Each agent/extension thread polls ITS OWN flag instead of
    /// the node-wide one, so the daemon can stop a single agent
    /// ([`Self::stop_agent`]) without tearing down the node — the generic
    /// lifecycle primitive that subsumes the http-gateway's bespoke `inner.stop`.
    /// A node-wide shutdown sets every flag here (see
    /// [`Self::signal_node_shutdown`]), so existing teardown is unchanged.
    agent_shutdown: AgentShutdown,
    /// Per-agent descriptive metadata (`id.0 → info`), populated
    /// at register time. Backs the generic `__describe` host primitive
    /// ([`Self::describe_agent`]) so `vosx <agent> describe` can report an
    /// agent's name / kind / serve address / running flag uniformly — the
    /// liveness half of the lifecycle surface that replaces the http-gateway's
    /// bespoke `status` invoke sidecar. Keyed on the full (prefix-scoped) id,
    /// matching [`Self::agent_shutdown`].
    agent_info: AgentInfos,
    /// Last time anything happened on the node — outbox routing,
    /// agent dispatch, worker dispatch, invoke handling. Updated
    /// by both threads and the routing loop. Read by
    /// [`run_until_idle`] to decide when to wind the node down.
    ///
    /// [`run_until_idle`]: VosNode::run_until_idle
    last_activity: ActivityClock,
    /// Optional libp2p network handle. Shared with all agent
    /// threads so cross-node `external_invoke` works regardless of
    /// whether the network was attached before or after agent
    /// registration. `None` inside the `Mutex` until
    /// [`attach_network`](Self::attach_network) runs.
    #[cfg(feature = "network")]
    pub(crate) shared_network: SharedNetwork,
    /// This daemon's operator: the PeerId bytes of the CLI identity that
    /// ran `vosx space up` (loaded in-process from the operator's
    /// `vosx/identity.key`). A node-confined agent — the messenger holds
    /// device-private MLS keys, the CSPRNG seed and decrypted plaintext —
    /// is reachable over the network ONLY by this exact caller (see
    /// [`NodeService::dispatch_invoke`]): the operator drives their own
    /// messenger with `vosx messenger …`, which dials the daemon as a
    /// libp2p call from THIS identity, while every other peer — including a
    /// remote admin of the same space — is refused. `None` (the default:
    /// a raw `vosx run`, a transient peer, or a test node) fails closed, so
    /// no peer reaches a confined agent. Set by
    /// [`set_operator_peer`](Self::set_operator_peer) before
    /// [`attach_network`](Self::attach_network).
    #[cfg(feature = "network")]
    operator_peer: Option<Vec<u8>>,
    /// Signs the space-registry's catalog mutators on relay with the
    /// operator key the daemon loaded at boot (the "sign on relay"
    /// seam). Handed to the registry agent thread, which injects the
    /// `auth` blob before recording so a keyless PVM agent's (or the
    /// in-process reconcile's) `install`/`publish`/… authorizes on the
    /// operator's node. `None` (a raw `vosx run` or a test node) leaves
    /// catalog ops unsigned, so the registry refuses them — fail closed.
    /// Set by [`set_operator_signer`](Self::set_operator_signer).
    operator_signer: Option<crate::registry::CatalogOpSigner>,
    /// Map: replication group → local replica handle.
    /// Populated by `register` whenever a CRDT actor with a
    /// `replication_id` is added. Read by [`NodeService`] (db
    /// only) to answer inbound sync queries; the agent thread
    /// and sync ticker share the `commit_lock` to serialize
    /// their writes against each other.
    #[cfg(all(feature = "network", feature = "storage"))]
    pub(crate) crdt_replicas: Arc<Mutex<HashMap<[u8; 32], ReplicaSlot>>>,
    /// Map: ServiceId word → replication group, for agents running
    /// the multi-mode Raft worker. Shared into every extension
    /// thread (via [`RaftFwd`]) so the ask path can recognize a
    /// follower-rejected write and re-address it to the group's
    /// current leader.
    #[cfg(all(feature = "network", feature = "storage"))]
    raft_hosts: RaftHosts,
    /// Optional manifest payload exposed to peers via
    /// [`Frame::ManifestReq`](crate::network::Frame::ManifestReq).
    /// Populated by [`set_manifest`](Self::set_manifest) before
    /// [`attach_network`](Self::attach_network) — vosx loads the
    /// space.toml + actor blobs and stashes them here so the
    /// `NetworkService` impl can serve them when a `vosx join`er
    /// asks. Set-once; `None` for nodes that don't expose a
    /// manifest (transient peers, manifest-less raw `vosx run`).
    #[cfg(feature = "network")]
    pub(crate) manifest: Arc<OnceLock<crate::network::ManifestReply>>,
    /// Join handles for the per-replica sync threads spawned
    /// by [`spawn_sync_thread`]. We keep these so [`collect`]
    /// can wait for the threads to exit before returning —
    /// otherwise the threads outlive the node, hold open
    /// `Arc<redb::Database>` references, and the next
    /// `redb::Database::create` against the same file fails
    /// with `Database already open. Cannot acquire lock`.
    #[cfg(all(feature = "network", feature = "storage"))]
    sync_threads: Vec<thread::JoinHandle<()>>,
    /// Content-addressed store for large opaque blobs (today: STARK
    /// proof bodies; future: any payload too big to ride inline
    /// through the PVM dispatch envelope). Keyed by domain-tagged
    /// blake2b-256 of the bytes — see [`Self::put_proof_blob`].
    ///
    /// Always-on in-memory hot cache. When
    /// [`proof_blobs_dir`](Self::proof_blobs_dir) is set, every
    /// `put` writes through to disk and every on-miss `get` lazy-
    /// loads from disk, so restarts don't lose cached proofs.
    pub(crate) proof_blobs: ProofBlobStore,
    /// Optional persistent backing for the proof-blob CAS. When
    /// `Some`, blobs land at `{dir}/{hex_hash}` on `put`, and a
    /// hot-cache miss falls back to a read from that path before
    /// returning `None`. `None` keeps the store pure in-memory —
    /// matches the legacy behaviour and is what tests use unless
    /// they explicitly opt in.
    pub(crate) proof_blobs_dir: Option<std::path::PathBuf>,
}

/// Shared content-addressed proof-blob store. Cheap to clone; both
/// the node's `Self` and any extension threads that need to look up
/// blobs receive an `Arc` to the same `RwLock<HashMap<...>>`.
pub(crate) type ProofBlobStore = Arc<RwLock<HashMap<[u8; 32], Vec<u8>>>>;

/// Content address for a proof blob. Domain-tagged blake2b-256 so
/// the namespace can't collide with other hash uses on the node
/// (replication IDs, CRDT CIDs, etc.).
pub fn proof_blob_hash(bytes: &[u8]) -> [u8; 32] {
    crate::crypto::blake2b::blake2b_hash::<32>(b"vos/proof-blob/v1", &[bytes])
}

/// Lower-case hex encoding of a proof-blob hash. Used as the
/// filename under [`VosNode::proof_blobs_dir`].
fn proof_blob_filename(hash: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in hash {
        use core::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

/// Shared handle for one CRDT replication group. The same
/// `Arc<Database>` powers the agent's `CrdtCommit` and the
/// sync layer's `SyncHandler`; the `commit_lock` serializes
/// the agent's `commit_with_log` against the sync ticker's
/// `insert_node` + `compact_roots`.
#[cfg(all(feature = "network", feature = "storage"))]
#[derive(Clone)]
pub(crate) struct ReplicaSlot {
    pub db: Arc<redb::Database>,
    pub commit_lock: Arc<Mutex<()>>,
    /// Installed instance name of the replica, used by the sync-serve
    /// path to membership-gate private (`msg-*`) groups. Empty for
    /// anonymous/test replicas — those serve openly (ungated).
    pub name: String,
    /// Per-replica gate applied to peer-merged nodes on the SYNC INGEST
    /// path (`sync_with_peer` → `insert_node`) — this is where peer
    /// nodes actually enter the DAG, so the registry's genesis validator
    /// must live here, not just on the agent thread's strategy. `None`
    /// accepts all peer nodes.
    pub node_validator: Option<crate::commit::NodeValidator>,
}

/// Shared invoke-route table. Cheap to clone and pass to threads.
type InvokeRoutes = Arc<Mutex<HashMap<u32, mpsc::Sender<InvokeRequest>>>>;

/// Shared map of raft-hosted agents: ServiceId word → replication
/// group of the multi-mode worker spawned for it. The companion to
/// `InvokeRoutes` for leader forwarding: where `InvokeRoutes`
/// answers "which channel reaches this ServiceId?", this answers
/// "which Raft group does it belong to?" so [`route_invoke`] can
/// consult the local worker's role/leader-hint when the local
/// replica drops a write.
#[cfg(all(feature = "network", feature = "storage"))]
type RaftHosts = Arc<Mutex<HashMap<u32, [u8; 32]>>>;

/// Shared host-side reverse map: `local_id` (`id.0 & 0xFFFF`) →
/// installed instance name. The companion to `InvokeRoutes` for the
/// auth path: where `InvokeRoutes` answers "which channel reaches this
/// ServiceId?", this answers "what instance name *is* this ServiceId?"
/// so the libp2p gate ([`NodeService::dispatch_invoke`]) and extension
/// relays (the actor-mode `EFFECT_ASK_DISPATCH` fulfiller) can resolve a
/// target's name for actor-local grant probes and `intra_caps`
/// enforcement.
///
/// Keyed on the **low 16 bits** because `instance_service_id` hashes the
/// name into the local half and ORs the node prefix into the high half
/// (see `space_registry::instance_service_id`); the name↔local_id
/// relation is therefore prefix-independent — a replica of the same
/// instance on another node shares the entry. Distinct names *can*
/// collide in the ~15-bit local space; the map is last-writer-wins on
/// collision (the registry's id derivation has the same exposure) and
/// `register_*_inner` logs a WARN when an insert overwrites a different
/// name. `RwLock` because reads are hot (every dispatch / relay) and
/// writes happen once per `register`.
type AgentNames = Arc<std::sync::RwLock<HashMap<u16, String>>>;

/// Descriptive metadata for one registered agent, captured at register
/// Time for the generic `__describe` host primitive.
/// `kind` mirrors [`crate::extension::ExtensionKind`] as a byte
/// (`0` actor, `2` transport; `1` service is unused);
/// `serves_addr` is the host-bound listen endpoint for a transport
/// extension (`None` otherwise).
#[derive(Clone)]
struct AgentInfo {
    name: Option<String>,
    kind: u8,
    serves_addr: Option<String>,
    /// Effective (post-seal) consistency tier for an actor agent, or
    /// `None` for a native extension (which has no tier). Read by
    /// [`NodeService::dispatch_invoke`] to refuse inbound *remote* calls
    /// to a node-confined agent — see [`Consistency::is_node_confined`].
    consistency: Option<Consistency>,
    /// Whether this agent opted OUT of the device-private network gate
    /// (see [`AgentConfig::network_reachable`]). When `true`, a
    /// `Local`/`Ephemeral` agent still answers remote peer invokes — for
    /// authoritative-but-network-served single-node state (a per-node
    /// authoritative store, a bridge). Ignored for `Crdt`/`Raft` (never
    /// confined).
    network_reachable: bool,
}

/// Shared per-agent shutdown flags (`id.0 → flag`). `Arc<Mutex>` so the
/// network-side [`NodeService`] sees agents registered after
/// `attach_network` — the `__stop` interceptor flips a flag here.
type AgentShutdown = Arc<Mutex<HashMap<u32, Arc<AtomicBool>>>>;

/// Shared per-agent descriptive metadata (`id.0 → info`). `Arc<RwLock>`
/// for the same reason as [`AgentShutdown`]; the `__describe`
/// interceptor reads it.
type AgentInfos = Arc<std::sync::RwLock<HashMap<u32, AgentInfo>>>;

/// Render one agent's [`AgentInfo`] + live `running` flag as the JSON
/// object the `__describe` primitive replies with (hand-built — vos has
/// no `serde_json` dep). Shape:
/// `{"id":N,"name":"…","kind":K,"serves_addr":"…"|null,"running":bool}`.
fn describe_agent_json(id: u32, info: &AgentInfo, running: bool) -> String {
    let name = json_escape(info.name.as_deref().unwrap_or(""));
    let serves = match &info.serves_addr {
        Some(a) => format!("\"{}\"", json_escape(a)),
        None => "null".to_string(),
    };
    format!(
        "{{\"id\":{id},\"name\":\"{name}\",\"kind\":{},\"serves_addr\":{serves},\"running\":{running}}}",
        info.kind,
    )
}

/// Minimal JSON string escaper for the handful of fields `__describe`
/// emits (agent names + listen addresses). Escapes the two characters
/// that would break a JSON string literal; other control characters are
/// not expected in manifest-derived identifiers.
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Mask a (possibly prefix-scoped) `ServiceId` value down to its
/// prefix-independent local id — the key space of [`AgentNames`].
fn local_id_of(svc_id: u32) -> u16 {
    (svc_id & 0xFFFF) as u16
}

/// Thread-safe handle for invoking local services. Returned by
/// [`VosNode::invoke_handle`] so background tasks can keep
/// calling into the node while [`VosNode::run_forever`] holds
/// the main thread.
///
/// Local-only — cross-node invokes need the attached network,
/// which lives on `VosNode` proper. Drop this handle when the
/// background task is done; the node's lifetime is unaffected.
pub struct InvokeHandle {
    invoke_routes: InvokeRoutes,
    shutdown: Arc<AtomicBool>,
}

impl InvokeHandle {
    /// Synchronously invoke `target`. Returns `None` when the
    /// target isn't a local service or the call times out.
    pub fn invoke_with_timeout(
        &self,
        target: ServiceId,
        msg: Vec<u8>,
        timeout: Duration,
    ) -> Option<Vec<u8>> {
        let tx = {
            let map = self.invoke_routes.lock().ok()?;
            map.get(&target.0).cloned()
        };
        let tx = tx?;
        let (reply_tx, reply_rx) = mpsc::channel();
        tx.send(InvokeRequest {
            // Host-side API entry: the embedder calling into the
            // daemon from inside the process. `Caller::System`
            // bypasses role checks via the trust shortcut so
            // host-side bootstrap (admin grant before any peer
            // is enrolled) and test harness calls don't hit the
            // M6 macro-emitted gate.
            caller: crate::actors::Caller::System,
            space_role: None,
            actor_local_role: None,
            msg,
            reply: ReplyChannel::Sync(reply_tx),
            chain: Vec::new(),
        })
        .ok()?;
        // Strip the cross-thread invoke envelope down to reply
        // bytes for host-side callers — see `VosNode::invoke`.
        reply_rx
            .recv_timeout(timeout)
            .ok()
            .and_then(|env| unwrap_invoke_envelope(&env))
    }

    /// `true` once the owning [`VosNode`] has been told to shut
    /// down. Background loops poll this so they exit cleanly.
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }
}

/// Shared pointer to the (optional) attached libp2p network. Agent
/// threads grab a clone at spawn time and check it on every
/// `external_invoke` so a `Network` attached *after* registration
/// still gets used. `None` until [`VosNode::attach_network`] is
/// called.
#[cfg(feature = "network")]
type SharedNetwork = Arc<Mutex<Option<Arc<crate::network::Network>>>>;

/// Single inbound-frame service for the node. Combines what used
/// to be three separate trait impls (invoke / sync / manifest)
/// behind one [`NetworkService`](crate::network::NetworkService)
/// installation. Each method either delegates to a node-owned
/// table (invoke routes, CRDT replicas) or returns the data the
/// host pre-stashed (manifest).
///
/// Constructed in [`VosNode::attach_network`] from the node's
/// already-existing tables; the manifest slot is populated by the
/// host (`vosx space up`) before `attach_network` runs.
#[cfg(feature = "network")]
struct NodeService {
    invoke_routes: InvokeRoutes,
    /// Clone of the node's [`AgentNames`] reverse map, read by
    /// [`Self::dispatch_invoke`] to resolve the target's instance name
    /// for the actor-local grant probe — so an operator-written
    /// actor-local grant enforces for *any* installed agent, not just
    /// the registry.
    agent_names: AgentNames,
    /// Clones of the node's per-agent shutdown flags +
    /// descriptive metadata so the `__stop` / `__describe` interceptor in
    /// [`Self::dispatch_invoke`] can stop/describe ANY agent by id —
    /// generic across actor / service / transport agents.
    agent_shutdown: AgentShutdown,
    agent_info: AgentInfos,
    #[cfg(feature = "storage")]
    replicas: Arc<Mutex<HashMap<[u8; 32], ReplicaSlot>>>,
    manifest: Arc<OnceLock<crate::network::ManifestReply>>,
    proof_blobs: ProofBlobStore,
    proof_blobs_dir: Option<std::path::PathBuf>,
    /// This daemon's operator PeerId bytes (a clone of
    /// [`VosNode::operator_peer`], set at [`VosNode::attach_network`]). The
    /// sole caller [`Self::dispatch_invoke`] admits to a node-confined
    /// target. `None` denies every caller (fail closed).
    operator_peer: Option<Vec<u8>>,
    /// Per-instance-name `SyncFloor` cache for the sync-serve gate. The
    /// floor is a static install-time property, but resolving it hits the
    /// registry with a blocking probe (up to ~5 s); caching keeps
    /// `FetchHeads`/`FetchNode` cheap under a chatty mesh. Entries expire
    /// after [`SYNC_FLOOR_TTL`] so an `install` that sets a floor is
    /// picked up without a restart.
    #[cfg(feature = "storage")]
    sync_floor_cache: SyncFloorCache,
}

/// Cache of resolved sync floors, keyed by replica instance name.
#[cfg(feature = "storage")]
type SyncFloorCache = Arc<RwLock<HashMap<String, (crate::registry::SyncFloor, Instant)>>>;

/// How long a cached `SyncFloor` stays fresh before it's re-probed.
#[cfg(feature = "storage")]
const SYNC_FLOOR_TTL: Duration = Duration::from_secs(30);

#[cfg(feature = "network")]
impl NodeService {
    /// Sprint 2 auth lookup. Send a synchronous `peer_role` invoke
    /// to the local space-registry and surface the result as the
    /// `AUTH_ROLE_*` byte the gate compares against. Returns
    /// `AUTH_ROLE_NONE` (= "deny") for any of:
    ///
    /// - `caller_peer_id == None` — in-process calls don't have
    ///   a libp2p identity (no current callers, but defensive).
    /// - registry route missing — gate fires before the registry
    ///   boots? bail safe.
    /// - registry reply empty / undecodable.
    ///
    /// Cheap (~1 short round-trip on local mpsc) but a hot
    /// frequent-call surface; the response is the registry's
    /// already-cached in-memory `auth_grants` Vec lookup.
    fn lookup_caller_role(&self, caller_peer_id: Option<&libp2p::PeerId>) -> u8 {
        let Some(peer_id) = caller_peer_id else {
            return AUTH_ROLE_NONE;
        };
        // Build a `peer_role` Msg with the caller's PeerId bytes.
        use crate::actors::codec::Encode;
        use crate::value::{Msg, TAG_DYNAMIC};
        let msg = Msg::new("peer_role").with("peer_id", peer_id.to_bytes());
        let mut payload = Vec::with_capacity(1 + 64);
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&msg.encode());
        self.probe_registry_for_u8(payload)
            .unwrap_or(AUTH_ROLE_NONE)
    }

    /// M5 — actor-local role probe. Sibling of
    /// [`Self::lookup_caller_role`] for the actor-local override
    /// table. Looks up the byte the registry's `actor_role`
    /// handler returns; `AUTH_ROLE_NONE` for "no row" so the
    /// caller can map back to `Option::None` cleanly.
    ///
    /// `agent_name` is the *target* actor's instance name —
    /// `"space-registry"` for the well-known registry target,
    /// the manifest-installed name for others. For v1, only the
    /// registry target gets this probe; non-registry targets
    /// require a service-id → name reverse lookup that a later
    /// commit will add.
    fn lookup_caller_actor_role(
        &self,
        caller_peer_id: Option<&libp2p::PeerId>,
        agent_name: &str,
    ) -> u8 {
        let Some(peer_id) = caller_peer_id else {
            return AUTH_ROLE_NONE;
        };
        use crate::actors::codec::Encode;
        use crate::value::{Msg, TAG_DYNAMIC};
        let msg = Msg::new("actor_role")
            .with("peer_id", peer_id.to_bytes())
            .with("agent_name", agent_name);
        let mut payload = Vec::with_capacity(1 + 64);
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&msg.encode());
        self.probe_registry_for_u8(payload)
            .unwrap_or(AUTH_ROLE_NONE)
    }

    /// Probe the local space-registry's `node_role` handler for the
    /// NODE member enrolled at `prefix`. Reply byte: `0` = not enrolled,
    /// `1` = VOTER, `2` = OBSERVER (the registry encodes `role + 1`; see
    /// `space_registry::node_role`). `0` on an unreachable/undecodable
    /// reply — the caller treats that as "deny".
    #[cfg(feature = "network")]
    fn lookup_node_role(&self, prefix: u16) -> u8 {
        use crate::actors::codec::Encode;
        use crate::value::{Msg, TAG_DYNAMIC};
        let msg = Msg::new("node_role").with("prefix", prefix as u64);
        let mut payload = Vec::with_capacity(1 + 16);
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&msg.encode());
        self.probe_registry_for_u8(payload).unwrap_or(0)
    }

    /// Membership gate for serving a replica's sync data (heads / nodes),
    /// keyed on the replica's [`SyncFloor`](crate::registry::SyncFloor):
    /// `Public` serves any connected peer; `Member` requires a space read
    /// grant (`>= READONLY`); `Private` requires that OR a per-actor read
    /// grant — the generalized `msg-*` semantics (an E2EE channel ships
    /// ciphertext, safe to sync to any member, plus non-member channel
    /// grantees). `caller == None` (no libp2p identity) is refused for any
    /// non-`Public` floor.
    #[cfg(feature = "storage")]
    fn sync_serve_allowed(&self, caller_peer_id: Option<&libp2p::PeerId>, name: &str) -> bool {
        use crate::registry::SyncFloor;
        match self.resolve_sync_floor(name) {
            SyncFloor::Public => true,
            SyncFloor::Member => {
                let Some(peer) = caller_peer_id else {
                    return false;
                };
                self.lookup_caller_role(Some(peer)) >= AUTH_ROLE_READONLY
                    || self.caller_is_enrolled_node(peer)
            }
            SyncFloor::Private => {
                let Some(peer) = caller_peer_id else {
                    return false;
                };
                self.lookup_caller_role(Some(peer)) >= AUTH_ROLE_READONLY
                    || self.lookup_caller_actor_role(Some(peer), name) >= AUTH_ROLE_READONLY
            }
        }
    }

    /// A node enrolled in the space (voter/observer) IS a space member —
    /// admin-gated `add_node` put it there — so it may sync `Member`-floor
    /// state (the registry it bootstraps from, app CRDTs) even before it
    /// holds a separate READONLY grant. This unwedges the join → sync →
    /// grant order: a joiner enrolled as a voter can pull the registry to
    /// learn the space before an operator grants it a role. `Private`
    /// (`msg-*`) deliberately does NOT accept enrollment here — a voter
    /// isn't automatically a channel reader; that stays grant-based.
    #[cfg(feature = "network")]
    fn caller_is_enrolled_node(&self, peer: &libp2p::PeerId) -> bool {
        self.lookup_node_role(crate::network::derive_node_prefix(peer)) > 0
    }

    /// No-network build: enrollment can't be probed, so fall back to the
    /// grant-only membership test.
    #[cfg(not(feature = "network"))]
    fn caller_is_enrolled_node(&self, _peer: &libp2p::PeerId) -> bool {
        false
    }

    /// Resolve a replica's serving floor from its instance name. The two
    /// registries are hardcoded (decision 9): the space registry serves at
    /// `Member` — a joiner redeems by remote invoke (ungated) BEFORE it can
    /// sync, so it holds a grant by the time its `FetchHeads` runs — and
    /// the hyperspace registry at `Public` (the federation surface).
    /// Anonymous / test replicas (empty name) serve openly. Every other
    /// replica's floor is its `AgentRow.sync_role`, probed once and cached
    /// with a short TTL; a probe miss defaults to `Member` — fail toward
    /// gated, never open.
    #[cfg(feature = "storage")]
    fn resolve_sync_floor(&self, name: &str) -> crate::registry::SyncFloor {
        use crate::registry::SyncFloor;
        match name {
            "" => return SyncFloor::Public,
            // The space registry stays PUBLIC until the redeem flow lands
            // (wave 3). A `Member` registry deadlocks bootstrap: a joiner
            // must sync the registry to LEARN its own grant, but a `Member`
            // gate would refuse it until it is already a member. The
            // ordering note in the plan resolves this by having the joiner
            // redeem (an ungated remote invoke) FIRST — which grants its
            // NODE key (the sync identity) — before it syncs. Until
            // `redeem_invite` is wired into `space up`, the old join flow
            // grants the OPERATOR (not the node) and enrolls the node only
            // later, so flipping the registry to `Member` now breaks the
            // join → sync → learn-grant order. Registry metadata is
            // non-secret, so `Public` is safe in the interim; the flip
            // rides with wave 3.
            REGISTRY_AGENT_NAME => return SyncFloor::Public,
            HYPERSPACE_REGISTRY_AGENT_NAME => return SyncFloor::Public,
            _ => {}
        }
        if let Ok(cache) = self.sync_floor_cache.read() {
            if let Some((floor, at)) = cache.get(name) {
                if at.elapsed() < SYNC_FLOOR_TTL {
                    return *floor;
                }
            }
        }
        let floor = self.probe_agent_floor(name).unwrap_or(SyncFloor::Member);
        if let Ok(mut cache) = self.sync_floor_cache.write() {
            cache.insert(name.to_string(), (floor, Instant::now()));
        }
        floor
    }

    /// Probe the registry's `agent(name)` handler and read the row's
    /// `sync_role`. `None` when the registry is unreachable, the agent
    /// isn't installed, or the reply doesn't decode.
    #[cfg(all(feature = "storage", feature = "network"))]
    fn probe_agent_floor(&self, name: &str) -> Option<crate::registry::SyncFloor> {
        use crate::actors::codec::{Decode, Encode};
        use crate::value::{Msg, TAG_DYNAMIC, Value};
        let msg = Msg::new("agent").with("instance_name", name);
        let mut payload = Vec::with_capacity(1 + 64);
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&msg.encode());
        let reply = registry_probe_reply(&self.invoke_routes, payload)?;
        // `agent` replies `Value::Bytes(rkyv AgentRow)` (installed) or
        // `Value::Unit` (not installed).
        match <Value as Decode>::try_decode(&reply)? {
            Value::Bytes(b) => {
                let row = <crate::registry::AgentRow as Decode>::try_decode(&b)?;
                Some(row.sync_role)
            }
            _ => None,
        }
    }

    /// Storage-only build (no network): the floor probe is unavailable, so
    /// gate every non-registry replica at `Member` — the same restrictive
    /// default a probe miss falls back to.
    #[cfg(all(feature = "storage", not(feature = "network")))]
    fn probe_agent_floor(&self, _name: &str) -> Option<crate::registry::SyncFloor> {
        None
    }

    /// Shared probe helper for both auth lookups — sends an
    /// already-encoded dynamic Msg to the registry, decodes the
    /// reply as a single `u8`. Returns `None` if the registry is
    /// unreachable (gate fires before registry boots), the reply
    /// times out, or the reply payload doesn't decode.
    fn probe_registry_for_u8(&self, payload: Vec<u8>) -> Option<u8> {
        registry_probe_u8(&self.invoke_routes, payload)
    }

    /// Resolve a (possibly prefix-scoped) target `ServiceId` value back
    /// to the installed instance name registered for it. Reads the
    /// node's shared [`AgentNames`] reverse map; `None` for ids this
    /// node never registered. Mirror of [`VosNode::agent_name_for`]
    /// over the cloned handle the network service holds.
    fn agent_name_for(&self, svc_id: u32) -> Option<String> {
        self.agent_names
            .read()
            .ok()?
            .get(&local_id_of(svc_id))
            .cloned()
    }

    /// Host-side handler for the reserved `__stop` / `__describe` wire
    /// Methods. Returns `Some(reply_bytes)` when the
    /// invoke's `Msg.name` is one of them (already answered), `None` to let
    /// `dispatch_invoke` forward the invoke normally. The reply matches the
    /// raw-`Value` shape `dispatch_invoke` otherwise returns: empty (→
    /// `Value::Unit` → client renders `null`) for `__stop`, an rkyv
    /// `Value::Str(json)` for `__describe`. Tries the scoped id first, then the
    /// unscoped fallback (a locally-registered agent lives under the low 16
    /// bits) — same two-step lookup as the route table.
    ///
    /// **Authorized**: these are host-enforced control ops that bypass the
    /// target actor's own `#[msg(role=…)]` gate, so they carry their own
    /// space-role check against the caller's grant (`lookup_caller_role`):
    /// `__stop` (privileged — stops an agent) requires **ADMIN**; `__describe`
    /// (reads name/kind/listen-addr) requires any space member (≥ read-only).
    /// An unauthorized caller (incl. an anonymous / non-member peer) gets a
    /// `STATUS_FORBIDDEN` envelope, NOT a silent stop/enumerate. The role
    /// lookup runs only after a reserved name matches, so normal dispatch
    /// pays nothing.
    fn try_intercept_lifecycle(
        &self,
        to: u32,
        to_unscoped: u32,
        msg: &[u8],
        caller_peer_id: Option<&libp2p::PeerId>,
    ) -> Option<Vec<u8>> {
        let name = intercepted_method_name(msg)?;
        match name.as_str() {
            "__stop" => {
                if self.lookup_caller_role(caller_peer_id) < AUTH_ROLE_ADMIN {
                    warn!(target = to, "__stop refused: caller lacks ADMIN role");
                    return Some(forbidden_envelope());
                }
                let stopped = self.stop_agent_id(to)
                    || (to != to_unscoped && self.stop_agent_id(to_unscoped));
                if !stopped {
                    warn!(target = to, "__stop: no agent registered under id");
                }
                // Value::Unit ⇒ empty reply (the client decodes empty as Unit).
                Some(Vec::new())
            }
            "__describe" => {
                if self.lookup_caller_role(caller_peer_id) == AUTH_ROLE_NONE {
                    warn!(
                        target = to,
                        "__describe refused: caller is not a space member"
                    );
                    return Some(forbidden_envelope());
                }
                let json = self.describe_agent_id(to).or_else(|| {
                    (to != to_unscoped)
                        .then(|| self.describe_agent_id(to_unscoped))
                        .flatten()
                });
                match json {
                    Some(j) => Some(crate::Encode::encode(&crate::value::Value::Str(j))),
                    // Unknown agent ⇒ empty (Unit); the CLI surfaces "no such agent".
                    None => Some(Vec::new()),
                }
            }
            _ => None,
        }
    }

    /// Flip one agent's shutdown flag by id (the `__stop` primitive's core).
    /// `false` when no agent is registered under `id`.
    fn stop_agent_id(&self, id: u32) -> bool {
        match self
            .agent_shutdown
            .lock()
            .ok()
            .and_then(|m| m.get(&id).cloned())
        {
            Some(flag) => {
                flag.store(true, Ordering::Relaxed);
                true
            }
            None => false,
        }
    }

    /// `true` when `to` resolves to a node-confined agent this node
    /// registered (consistency `Local`/`Ephemeral`). Mirrors the
    /// `dispatch_invoke` route lookup's scoped/unscoped fallback. A missing
    /// entry (anonymous, cross-node, or never-registered target) is treated
    /// as *not* confined — the route lookup then handles it normally — so
    /// the gate only ever restricts agents this node knows to be device-
    /// private. See [`Self::dispatch_invoke`].
    fn target_is_node_confined(&self, to: u32, to_unscoped: u32) -> bool {
        let Ok(info) = self.agent_info.read() else {
            return false;
        };
        let entry = info
            .get(&to)
            .or_else(|| if to != to_unscoped { info.get(&to_unscoped) } else { None });
        entry.is_some_and(|i| {
            // A `network_reachable` opt-out keeps an authoritative-but-
            // network-served single-node agent (an authoritative store, a
            // bridge) reachable; only device-private agents stay confined.
            i.consistency.is_some_and(Consistency::is_node_confined) && !i.network_reachable
        })
    }

    /// `true` when `caller` is this daemon's own operator — the CLI identity
    /// that ran `vosx space up` ([`VosNode::set_operator_peer`]). The one
    /// caller admitted to a node-confined agent over the network: the
    /// operator drives their device-local messenger with `vosx messenger …`,
    /// which dials the daemon as a libp2p call from this identity. Fails
    /// closed — an unset operator (`None`), an anonymous caller (`None`), or
    /// any other PeerId (a remote peer, or even a remote admin of the same
    /// space) all return `false` — so confined plaintext never leaves the
    /// device. See [`Self::dispatch_invoke`].
    fn caller_is_operator(&self, caller: Option<&libp2p::PeerId>) -> bool {
        self.operator_peer
            .as_deref()
            .zip(caller)
            .is_some_and(|(op, p)| op == p.to_bytes().as_slice())
    }

    /// Render an agent's describe JSON by id (the `__describe` primitive's
    /// core). `None` when no agent is registered under `id`.
    fn describe_agent_id(&self, id: u32) -> Option<String> {
        let info = self.agent_info.read().ok()?.get(&id).cloned()?;
        let running = self
            .agent_shutdown
            .lock()
            .ok()
            .and_then(|m| m.get(&id).map(|f| !f.load(Ordering::Relaxed)))
            .unwrap_or(true);
        Some(describe_agent_json(id, &info, running))
    }
}

/// Send an already-encoded dynamic `Msg` to the local registry and
/// decode the reply as a single `u8`. The free-function core of the
/// auth probes, shared by [`NodeService::probe_registry_for_u8`] (the
/// libp2p gate) and [`relay_actor_local_role`] (extension relays),
/// which both have the routes table but not a `NodeService`. The probe
/// asserts `Caller::System` so it bypasses any role-gated registry read
/// handler. Returns `None` if the registry is unreachable, the reply
/// times out, or the payload doesn't decode.
#[cfg(feature = "network")]
fn registry_probe_reply(routes: &InvokeRoutes, payload: Vec<u8>) -> Option<Vec<u8>> {
    let registry_id = crate::abi::service::ServiceId::REGISTRY.local_id() as u32;
    let tx = routes.lock().ok()?.get(&registry_id).cloned()?;
    let (reply_tx, reply_rx) = mpsc::channel();
    if tx
        .send(InvokeRequest {
            caller: crate::actors::Caller::System,
            space_role: None,
            actor_local_role: None,
            msg: payload,
            reply: ReplyChannel::Sync(reply_tx),
            chain: vec![],
        })
        .is_err()
    {
        return None;
    }
    let envelope = reply_rx.recv_timeout(Duration::from_secs(5)).ok()?;
    unwrap_invoke_envelope(&envelope)
}

#[cfg(feature = "network")]
fn registry_probe_u8(routes: &InvokeRoutes, payload: Vec<u8>) -> Option<u8> {
    decode_u8_reply(&registry_probe_reply(routes, payload)?)
}

/// Pull a `u8` out of the actor-framework reply bytes. Handles
/// both the `Value::U8` wire shape and the `Value::Bytes(rkyv(u8))`
/// fallback. Sprint 2's auth lookup needs this; other host
/// callers stay with the dynamic Value decoder.
#[cfg(feature = "network")]
fn decode_u8_reply(bytes: &[u8]) -> Option<u8> {
    use crate::actors::codec::Decode;
    let value = <crate::value::Value as Decode>::try_decode(bytes)?;
    match value {
        crate::value::Value::U8(n) => Some(n),
        crate::value::Value::U32(n) => Some(n as u8),
        crate::value::Value::U64(n) => Some(n as u8),
        crate::value::Value::Bytes(b) => <u8 as Decode>::try_decode(&b),
        _ => None,
    }
}

/// Peek the dynamic-dispatch `Msg.name` out of an invoke payload
/// (`[TAG_DYNAMIC][rkyv Msg]`) for the lifecycle interceptor, without
/// disturbing the original bytes (they're still forwarded verbatim on a
/// non-match). `None` when the payload isn't a dynamic `Msg` (a raw/typed
/// invoke is never a reserved lifecycle verb) or fails to decode.
#[cfg(feature = "network")]
fn intercepted_method_name(msg: &[u8]) -> Option<String> {
    use crate::value::{Msg, TAG_DYNAMIC};
    if msg.first() != Some(&TAG_DYNAMIC) {
        return None;
    }
    <Msg as crate::Decode>::try_decode(&msg[1..]).map(|m| m.name)
}

#[cfg(feature = "network")]
impl crate::network::NetworkService for NodeService {
    fn dispatch_invoke(
        &self,
        caller_peer_id: Option<libp2p::PeerId>,
        _from: u32,
        to: u32,
        chain: Vec<u32>,
        msg: Vec<u8>,
    ) -> Vec<u8> {
        // The chain arrived already including the original caller's
        // ID (the remote peer's agent). The receiver's own
        // external_invoke prepends *this* agent's ID when dispatching
        // further hops, so we don't need to touch the chain here.
        //
        // Cross-network targets carry the receiver's `node_prefix` in
        // the upper 16 bits. Many agents (notably the well-known
        // registry at local_id 0) register themselves as unscoped
        // (`ServiceId(0, local_id)`), so a literal lookup of `to`
        // misses. Fall back to the unscoped form when the prefix
        // matches our own node — same routing decision the local
        // path makes via `is_on_node || is_local`.
        let to_unscoped = to & 0xFFFF;

        // Locality boundary: a node-confined agent (`Local`/`Ephemeral`)
        // holds device-private state — for the messenger, the MLS keys, the
        // CSPRNG seed and the decrypted plaintext history. The ONLY network
        // caller allowed to reach it is this daemon's own operator: the
        // device's human drives their messenger with `vosx messenger …`,
        // which dials the daemon as a libp2p call carrying the operator's CLI
        // identity (`Caller::Peer(<operator>)`). Every other peer is refused
        // — without this gate one could compute the name-derived ServiceId
        // and call `history` (read another node's plaintext), `seed` (inject
        // a known CSPRNG root) or `send`/`invite` (impersonate the member),
        // and a remote ADMIN of the same space is refused just the same: the
        // boundary is the device, not the space role. Refuse as if the agent
        // did not exist (empty reply — no existence oracle, matching the
        // unknown-target path below). Runs ahead of the lifecycle interceptor
        // so `__stop`/`__describe` of a confined agent are refused too. In-
        // process host calls (`VosNode::invoke` / `InvokeHandle`) never reach
        // this method, so local provisioning is unaffected.
        if self.target_is_node_confined(to, to_unscoped)
            && !self.caller_is_operator(caller_peer_id.as_ref())
        {
            warn!(
                target = to,
                peer = ?caller_peer_id,
                "invoke refused: node-confined agent is reachable only by this \
                 device's operator",
            );
            return Vec::new();
        }

        // Reserved generic lifecycle methods are answered
        // host-side, so `vosx <agent> stop|describe` works for ANY agent —
        // including transport extensions (the gateway) that have no inbound
        // `#[msg]` handler / invoke route at all. The method name lives inside
        // the rkyv `Msg`; this is the one place the host peeks it. The `__`
        // prefix keeps `__stop`/`__describe` from colliding with an actor's own
        // handler names. Replaces the gateway's deleted `vos_service_handle_invoke`
        // stop/status sidecar with a primitive uniform across all agent kinds.
        // It carries its OWN space-role gate (admin for stop, member for
        // describe) since it bypasses the target actor's `#[msg(role)]` check.
        if let Some(reply) =
            self.try_intercept_lifecycle(to, to_unscoped, &msg, caller_peer_id.as_ref())
        {
            return reply;
        }

        // The dispatch-layer role gate has moved to the actor's own
        // macro-emitted #[msg(role = X)] check
        // runs at the dispatch boundary inside the agent and
        // surfaces STATUS_FORBIDDEN through the wire envelope
        // (see vos/src/actors/lifecycle.rs::exit_status + the
        // runtime's last_status plumbing). The host stays
        // generic: it ferries the caller bytes; the actor
        // decides.

        let tx = self.invoke_routes.lock().ok().and_then(|m| {
            m.get(&to).cloned().or_else(|| {
                if to != to_unscoped {
                    m.get(&to_unscoped).cloned()
                } else {
                    None
                }
            })
        });
        let Some(tx) = tx else {
            return Vec::new();
        };
        let (reply_tx, reply_rx) = mpsc::channel();
        // libp2p noise verified the PeerId at connect time; the
        // multihash bytes are what the registry's grant table
        // keys on. `None` (in-process libp2p frame with no peer)
        // collapses to Unauthenticated.
        let caller = match caller_peer_id.as_ref() {
            Some(p) => crate::actors::Caller::Peer(p.to_bytes()),
            None => crate::actors::Caller::Unauthenticated,
        };
        // M5 — populate the role bytes for Peer callers so the
        // actor's M6 macro-emitted check has the inputs it needs.
        // Space-level grant always probed; actor-local grant probed
        // against whichever installed agent the target resolves to via
        // the host's reverse map. R2 generalised this beyond the
        // registry: an operator's `space role <agent> --in <agent>`
        // grant now enforces for *any* installed agent, not just
        // space-registry. Targets the host never registered (anonymous,
        // cross-node) resolve to `None` → no actor-local grant, which
        // is the correct deny-by-omission.
        let (space_role, actor_local_role) = match &caller {
            crate::actors::Caller::Peer(_) => {
                let space = self.lookup_caller_role(caller_peer_id.as_ref());
                let actor_local = match self.agent_name_for(to_unscoped) {
                    Some(name) => self.lookup_caller_actor_role(caller_peer_id.as_ref(), &name),
                    None => AUTH_ROLE_NONE,
                };
                (
                    (space != AUTH_ROLE_NONE).then_some(space),
                    (actor_local != AUTH_ROLE_NONE).then_some(actor_local),
                )
            }
            // Unauthenticated has no grant lookups; intra-system
            // Actor callers bypass via the Context::has_role
            // short-circuit.
            _ => (None, None),
        };

        // Private-replica read gate. A `Private`-floor replica (the
        // messenger's `msg-*` channel actors, or any app agent installed
        // `sync = "private"`) holds state the sync gate serves only to
        // members/grantees, and its READ handlers are bare `#[msg]` (no
        // role gate). The local owner reads its OWN replica through the
        // same-node invoke route and never reaches `dispatch_invoke`, so a
        // read arriving HERE is always a remote peer. Gate it by the same
        // membership floor the sync path uses ([`sync_serve_allowed`]): a
        // space member (or an actor-local read grant) may read; a
        // non-member is refused as if the method did not exist (empty
        // reply — no existence oracle). This only closes the invoke
        // backdoor that bypassed the sync gate. WRITE handlers (raft
        // leader-forward of `post` / `commit` / `publish_kp` / …) are NOT
        // gated here — they carry the actor's own `#[msg(role = …)]` check
        // and legitimately arrive over the network. Reuses the role bytes
        // already probed above; the floor lookup is cached.
        #[cfg(feature = "storage")]
        let target_is_private = self
            .agent_name_for(to_unscoped)
            .is_some_and(|name| self.resolve_sync_floor(&name) == crate::registry::SyncFloor::Private);
        #[cfg(not(feature = "storage"))]
        let target_is_private = false;
        if target_is_private
            && intercepted_method_name(&msg).is_some_and(|m| is_private_read_method(&m))
        {
            let is_member = space_role.is_some_and(|r| r >= AUTH_ROLE_READONLY)
                || actor_local_role.is_some_and(|r| r >= AUTH_ROLE_READONLY);
            if !is_member {
                warn!(
                    target = to,
                    peer = ?caller_peer_id,
                    "invoke refused: private replica read requires space membership",
                );
                return Vec::new();
            }
        }

        if tx
            .send(InvokeRequest {
                caller,
                space_role,
                actor_local_role,
                msg,
                reply: ReplyChannel::Sync(reply_tx),
                chain,
            })
            .is_err()
        {
            return Vec::new();
        }
        // The receiver replies with the full invoke envelope; the
        // libp2p protocol still ships only reply bytes, so unwrap
        // here. A future protocol bump can carry the envelope so
        // remote yielded children become drivable cross-node.
        //
        // M7 — STATUS_FORBIDDEN envelopes are preserved verbatim
        // so the client-side `is_forbidden_envelope` peek
        // surfaces ClientError::Forbidden ("permission denied").
        // Without this passthrough, the unwrap collapses the
        // refusal to an empty reply that vosx mis-decodes as
        // Value::Unit.
        //
        // Timeout budget mirrors the libp2p request_response side
        // (5 min) so slow handlers like the dev extension's
        // `compile` (cargo + rustc) don't get cut off here while
        // the wire layer is still patient.
        match reply_rx.recv_timeout(Duration::from_secs(300)).ok() {
            Some(env) => {
                if env.first().copied() == Some(crate::actors::run::STATUS_FORBIDDEN) {
                    let peer_label = caller_peer_id
                        .as_ref()
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "<local>".into());
                    warn!(
                        target = to,
                        peer = %peer_label,
                        "auth: actor refused call — caller lacks the required role",
                    );
                    return forbidden_envelope();
                }
                unwrap_invoke_envelope(&env).unwrap_or_default()
            }
            None => Vec::new(),
        }
    }

    #[cfg(feature = "storage")]
    fn sync_roots(
        &self,
        caller_peer_id: Option<libp2p::PeerId>,
        replication_id: &[u8; 32],
    ) -> Option<Vec<[u8; 32]>> {
        let slot = self.replicas.lock().ok()?.get(replication_id).cloned()?;
        if !self.sync_serve_allowed(caller_peer_id.as_ref(), &slot.name) {
            return None;
        }
        crate::commit::read_roots(&slot.db).ok()
    }

    #[cfg(feature = "storage")]
    fn sync_get_node(
        &self,
        caller_peer_id: Option<libp2p::PeerId>,
        replication_id: &[u8; 32],
        cid: &[u8; 32],
    ) -> Option<Vec<u8>> {
        let slot = self.replicas.lock().ok()?.get(replication_id).cloned()?;
        if !self.sync_serve_allowed(caller_peer_id.as_ref(), &slot.name) {
            return None;
        }
        crate::commit::read_dag_node(&slot.db, cid).ok().flatten()
    }

    fn manifest(&self) -> Option<crate::network::ManifestReply> {
        self.manifest.get().cloned()
    }

    fn get_proof_blob(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        // Hot cache first; disk fallback lazy-hydrates so a peer
        // that put the blob in a previous process incarnation can
        // still serve it. Mirrors `VosNode::get_proof_blob`.
        if let Some(bytes) = self.proof_blobs.read().ok()?.get(hash).cloned() {
            return Some(bytes);
        }
        let dir = self.proof_blobs_dir.as_ref()?;
        let bytes = std::fs::read(dir.join(proof_blob_filename(hash))).ok()?;
        if let Ok(mut store) = self.proof_blobs.write() {
            store.insert(*hash, bytes.clone());
        }
        Some(bytes)
    }

    /// Admit a Raft joiner only if it is enrolled as a `NODE_ROLE_VOTER`
    /// in the local space-registry. Fails **closed** — an unreachable or
    /// empty registry reply (`lookup_node_role` → `0` = "not enrolled")
    /// denies the join — so a peer an admin never enrolled cannot make
    /// itself a voter.
    fn raft_join_authorized(&self, prefix: u16) -> bool {
        self.lookup_node_role(prefix) == NODE_ROLE_REPLY_VOTER
    }
}

/// Replay every log in the strategy's DAG against `runtime`'s
/// state for `svc_id`. Used by both cold-start recovery and
/// mid-flight soft restarts after the sync ticker merges new
/// nodes. Caller is responsible for clearing prior state when
/// rebuilding from scratch — this function only feeds messages
/// through `begin_replay` and lets the actor produce state.
fn replay_dag_into_runtime(
    runtime: &mut VosRuntime,
    svc_id: ServiceId,
    strategy: &dyn crate::commit::CommitStrategy,
) -> Result<(), String> {
    let logs = strategy
        .replay_logs()
        .map_err(|e| format!("replay_logs failed: {e}"))?;
    if logs.is_empty() {
        return Ok(());
    }
    for (i, log) in logs.into_iter().enumerate() {
        let msg = log.msg.clone();
        // The (kind, anchor) recorded in this durable log node — the
        // state the ORIGINAL dispatch ran against. The replayed
        // dispatch must re-emit the same anchor, or the rebuilt state
        // history has diverged. This is the normative divergence check:
        // the guest's own anchor self-check passes by construction
        // during replay (it anchors whatever the runtime just served
        // it) and detects nothing.
        let recorded_anchor = (log.anchor_kind, log.anchor);
        let recorded_caller = log.caller_prefix;
        let _ = runtime.take_dispatch_anchor(svc_id);
        // Replayed dispatches populate the same per-dispatch delta
        // trackers real dispatches do; nothing commits them during
        // replay (the durable history already holds them), so drain
        // them — leaking a replayed dispatch's effect-bearing marker
        // into the next real dispatch would make a pure read on a Raft
        // follower propose (and fail NotLeader, dropping its reply).
        let _ = runtime.take_dispatch_delta(svc_id);
        runtime.begin_replay(log);
        // An empty-msg node is a recorded kick dispatch — the
        // host-synthesized wake-up whose whole semantic is "run
        // on_start". Replay it as exactly that: a raw empty payload
        // (never prefix-wrapped — the actor would strip the prefix
        // back to empty bytes and panic decoding them as a message;
        // the runtime instead filters the empty item and the guest
        // runs its cold-start path with no mail). Skipping these
        // nodes instead would drop on_start's state transition and
        // break the anchor chain for every node after.
        //
        // Non-empty dispatches replay under the RECORDED caller
        // prefix — the original caller's trust flag and role grants —
        // so every gate decision reproduces exactly: a role-refused
        // dispatch replays as refused (its durable node may still
        // carry framework effects like the genesis state write), a
        // granted one as granted. Legacy logs without a recorded
        // prefix decode as trusted-System, their historical replay
        // identity.
        if msg.is_empty() {
            runtime.send_to(svc_id, Vec::new());
        } else {
            runtime.send_to(svc_id, encode_replay_payload(&recorded_caller, &msg));
        }
        runtime.run_blocking();
        // External transfers emitted during replay had their
        // original effects at record time; we don't re-issue them.
        let _ = runtime.drain_external_transfers(svc_id);
        let replay = runtime.finish_replay().expect("replay was active");
        if !replay.is_complete() {
            return Err(format!(
                "replay diverged at log #{i} (pos={}, exhausted={}); \
                 handler is non-deterministic",
                replay.position(),
                replay.was_exhausted(),
            ));
        }
        let replayed_anchor = runtime.take_dispatch_anchor(svc_id);
        let _ = runtime.take_dispatch_delta(svc_id);
        if recorded_anchor.0 != crate::effect_log::ANCHOR_UNRECORDED
            && replayed_anchor != Some(recorded_anchor)
        {
            if strategy.linear_history() {
                return Err(format!(
                    "replay diverged at log #{i}: re-emitted work-result anchor \
                     {replayed_anchor:02x?} != recorded {recorded_anchor:02x?} — \
                     rebuilt state history differs from the committed one",
                ));
            }
            // Merged-DAG replay serializes concurrent branches into an
            // order their recorded anchors never observed — expected,
            // not divergence. Kept observable for diagnostics.
            debug!(
                %svc_id,
                log = i,
                ?replayed_anchor,
                ?recorded_anchor,
                "replayed anchor differs from recorded (merged-DAG serialization)",
            );
        }
    }
    Ok(())
}

/// Soft restart for a CRDT actor. Picks up whatever the sync
/// ticker merged into our redb file, throws away the locally-
/// derived runtime state, replays every log in the merged DAG,
/// and commits the rebuilt state plus the whole rebuilt keyspace
/// (see [`rebuilt_rows`] — merged remote dispatches' rows exist
/// nowhere else). Idempotent — calling it twice in a row produces
/// the same final state.
///
/// Called from the agent thread between dispatches when the
/// sync notifier fires, so blocking is fine. Returns `Err(msg)`
/// only on host-side errors (corrupt strategy, non-deterministic
/// handler) — caller logs and tears the agent down.
///
/// Only the sync-driven CRDT/Raft restart path calls this, and that
/// path needs the network (the sync notifier rides libp2p), so it's
/// gated `all(storage, network)` to match its callers — otherwise it's
/// dead code in a storage-only build.
#[cfg(all(feature = "storage", feature = "network"))]
fn soft_restart_crdt(
    runtime: &mut VosRuntime,
    svc_id: ServiceId,
    strategy: &mut dyn crate::commit::CommitStrategy,
) -> Result<(), String> {
    strategy
        .reload()
        .map_err(|e| format!("strategy.reload: {e}"))?;
    // Replay rebuilds every row by re-executing the guest from genesis,
    // so it must run against the empty slate a cold-boot replay sees —
    // not just a STATE_KEY-less one. The storage-type meta/index and
    // `StorageVec` length rows are accumulators: replaying inserts/pushes
    // onto the live pre-merge rows rebuilds a divergent physical layout
    // (and doubles a `StorageVec`'s length), which the state anchor does
    // not cover, so two replicas would silently stop being row-identical.
    // Wipe the whole keyspace and restore only INIT_KEY — the host-seeded
    // constructor input the genesis dispatch legitimately reads, which
    // replay never re-emits.
    let init = runtime
        .storage
        .read(svc_id, crate::lifecycle::INIT_KEY)
        .map(|v| v.to_vec());
    runtime.storage.clear_service(svc_id);
    if let Some(init) = init {
        runtime
            .storage
            .write(svc_id, crate::lifecycle::INIT_KEY, &init);
    }
    replay_dag_into_runtime(runtime, svc_id, strategy)?;
    let state = runtime
        .storage
        .read(svc_id, crate::lifecycle::STATE_KEY_BYTES)
        .map(|v| v.to_vec())
        .unwrap_or_default();
    if !state.is_empty() {
        // The soft-restart slate was seeded with INIT_KEY alone (above).
        let rows = rebuilt_rows(runtime, svc_id, &[crate::lifecycle::INIT_KEY]);
        strategy
            .commit_rebuilt(&state, &rows)
            .map_err(|e| format!("post-soft-restart commit: {e}"))?;
    }
    Ok(())
}

/// The rebuilt keyspace a replay left in the runtime, ready for
/// [`CommitStrategy::commit_rebuilt`]: every row except STATE_KEY
/// (which travels separately as the state blob), the continuation
/// header (host bookkeeping written outside dispatch deltas by
/// design — a replica applying the same history incrementally never
/// persists it, so persisting it here would break cross-replica
/// byte-parity and re-seed a dangling header whose flat_mem body is
/// gone), and `host_seeded` keys (rows the host writes from the
/// manifest on every spawn, INIT_KEY at minimum — persisting one
/// would let a stale copy shadow a manifest edit on the next boot).
///
/// Local dispatch deltas persist rows incrementally, but the rows a
/// replay produces for *merged remote* dispatches exist only here in
/// the runtime — without persisting the full slate, a cold reopen
/// (`restore_writes`) comes back missing every remotely-replicated
/// row, and a later local delta can persist index pages that name
/// value rows the table doesn't hold.
fn rebuilt_rows(
    runtime: &VosRuntime,
    svc_id: ServiceId,
    host_seeded: &[&[u8]],
) -> Vec<(Vec<u8>, Vec<u8>)> {
    runtime
        .storage
        .scan_prefix(svc_id, b"")
        .filter(|(key, _)| {
            *key != crate::lifecycle::STATE_KEY_BYTES
                && *key != crate::lifecycle::CONTINUATION_HEADER_KEY
                && !host_seeded.contains(key)
        })
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect()
}

/// How often the per-replica sync ticker fires. Short enough that
/// integration tests can observe convergence in a few hundred ms,
/// long enough that idle clusters don't flood the wire.
#[cfg(all(feature = "network", feature = "storage"))]
const SYNC_INTERVAL: Duration = Duration::from_millis(250);

/// Per-fetch deadline. Peers that disappear mid-handshake still
/// only steal this long from the ticker.
#[cfg(all(feature = "network", feature = "storage"))]
const SYNC_FETCH_TIMEOUT: Duration = Duration::from_secs(2);

/// Every Nth sync tick we re-probe all connected peers (not
/// just known group members) so newly-joined replicas of an
/// existing group get discovered. Picked to be a small
/// multiple of the tick interval — at 250ms × 8, that's a 2s
/// upper bound on discovering a new peer for a group we
/// already track.
#[cfg(all(feature = "network", feature = "storage"))]
const SYNC_REPROBE_EVERY: u64 = 8;

#[cfg(all(feature = "network", feature = "storage"))]
#[derive(Debug)]
enum SyncOutcome {
    /// Peer has the replication group. `inserted` is true iff
    /// at least one DAG node was new locally.
    PeerHasGroup { inserted: bool },
    /// Peer answered with empty heads — they don't (currently)
    /// host this group. Treated as a soft signal: the membership
    /// cache demotes them, but a full re-probe sweep
    /// (`SYNC_REPROBE_EVERY` ticks later) gives them another shot.
    PeerEmpty,
}

/// Background ticker for one replication group. Tracks which
/// connected peers have actually answered with non-empty heads
/// for this group and only fans the BFS pull out to those —
/// otherwise an N-peer / M-group cluster eats N×M FetchHeads
/// frames per tick. Every [`SYNC_REPROBE_EVERY`] ticks the
/// loop also probes peers it doesn't yet have membership info
/// for, picking up replicas that joined the group after the
/// initial discovery sweep.
///
/// Runs detached — exits when `shutdown` is set or every clone
/// of the relevant `Arc`s has been dropped (signalling the
/// network/node/db they reference is gone). When `notifier` is
/// `Some`, sends `()` after every cycle that brought in at
/// least one new node so the agent thread can soft-restart and
/// pick up the merged state.
#[cfg(all(feature = "network", feature = "storage"))]
fn sync_loop(
    rep_id: [u8; 32],
    shared_network: SharedNetwork,
    slot: ReplicaSlot,
    shutdown: Arc<AtomicBool>,
    notifier: Option<mpsc::Sender<()>>,
) {
    let mut confirmed: HashSet<libp2p::PeerId> = HashSet::new();
    let mut tick: u64 = 0;
    let mut subscribed = false;
    let (hint_tx, hint_rx) = mpsc::channel::<libp2p::PeerId>();
    while !shutdown.load(Ordering::Relaxed) {
        std::thread::sleep(SYNC_INTERVAL);
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        let Some(net) = shared_network.lock().ok().and_then(|g| g.clone()) else {
            continue;
        };
        // First time we see the network attached, subscribe to
        // the gossipsub topic and register our hint channel so
        // peer head announcements wake us up.
        if !subscribed {
            net.join_replication(rep_id, hint_tx.clone());
            subscribed = true;
        }
        let local = net.peer_id();
        let connected: HashSet<libp2p::PeerId> = net
            .connected_peers()
            .into_iter()
            .filter(|p| p != &local)
            .collect();
        // Drop peers that disconnected since our last tick.
        confirmed.retain(|p| connected.contains(p));

        // Drain pending gossipsub hints — peers that just
        // published heads. Each hint triggers an immediate
        // (single-peer) sync, bypassing the periodic poll.
        let mut hinted: Vec<libp2p::PeerId> = Vec::new();
        while let Ok(peer) = hint_rx.try_recv() {
            if peer != local && connected.contains(&peer) && !hinted.contains(&peer) {
                hinted.push(peer);
            }
        }

        // Reprobe sweep: every Nth tick (or whenever we have no
        // confirmed members yet) hit every connected peer to
        // find new group hosts. Otherwise stick to the cache
        // plus any hinted peers from the gossipsub side.
        let reprobe = tick.is_multiple_of(SYNC_REPROBE_EVERY) || confirmed.is_empty();
        tick = tick.wrapping_add(1);

        let mut targets: Vec<libp2p::PeerId> = if reprobe {
            connected.iter().copied().collect()
        } else {
            confirmed.iter().copied().collect()
        };
        for h in &hinted {
            if !targets.contains(h) {
                targets.push(*h);
            }
        }

        let mut any_inserted = false;
        for peer in targets {
            match sync_with_peer(&net, peer, &rep_id, &slot) {
                Ok(SyncOutcome::PeerHasGroup { inserted }) => {
                    confirmed.insert(peer);
                    if inserted {
                        any_inserted = true;
                    }
                }
                Ok(SyncOutcome::PeerEmpty) => {
                    // Demote — they're either out of the group
                    // or briefly empty during their own cold
                    // start. The next reprobe rediscovers them.
                    confirmed.remove(&peer);
                }
                Err(e) => warn!(error = %e, "sync: per-peer cycle failed"),
            }
        }
        if any_inserted && let Some(n) = &notifier {
            let _ = n.send(());
        }
    }
}

/// One pull cycle against a single peer for one replication
/// group. Returns:
///   - `PeerHasGroup { inserted }` when the peer answered with
///     non-empty heads (regardless of whether anything new was
///     pulled in)
///   - `PeerEmpty` when the peer reports no heads — interpreted
///     as "this peer doesn't host the group right now"
///
/// Errors only on host-side commit failures; transient network
/// failures surface as a timeout / disconnect, which we silently
/// treat as `PeerEmpty` for the membership cache (the next
/// reprobe sweep retries).
#[cfg(all(feature = "network", feature = "storage"))]
fn sync_with_peer(
    net: &crate::network::Network,
    peer: libp2p::PeerId,
    rep_id: &[u8; 32],
    slot: &ReplicaSlot,
) -> Result<SyncOutcome, crate::commit::CommitError> {
    use crate::commit::CrdtCommit;
    use crate::effect_log::CrdtEvent;
    use merkle_crdt::DagNode;

    let heads_rx = net.send_fetch_heads(peer, *rep_id);
    let heads = match heads_rx.recv_timeout(SYNC_FETCH_TIMEOUT) {
        Ok(v) => v,
        Err(_) => return Ok(SyncOutcome::PeerEmpty),
    };
    if heads.is_empty() {
        return Ok(SyncOutcome::PeerEmpty);
    }

    // Sync only inserts peer-produced DAG nodes; it never allocates
    // a fresh `(origin, seq)`. The replica_origin we hand the
    // strategy here would only matter if a local write slipped in
    // — derive it the same way the agent thread does so the two
    // CrdtCommits over the same redb agree on origin if they ever
    // both write.
    let replica_origin = derive_replica_origin(rep_id, net.local_prefix());
    let mut cc =
        CrdtCommit::from_db_arc_locked(slot.db.clone(), slot.commit_lock.clone(), replica_origin);
    // Gate peer nodes through the replica's validator (the registry binds
    // the genesis set_root to its space_id) — this is the ingest point.
    cc.set_node_validator(slot.node_validator.clone());
    let mut frontier: Vec<[u8; 32]> = heads.clone();
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut inserted_any = false;

    while let Some(cid) = frontier.pop() {
        if !seen.insert(cid) {
            continue;
        }
        if cc.get_node_bytes(&cid)?.is_some() {
            continue;
        }
        let node_rx = net.send_fetch_node(peer, *rep_id, cid);
        let Ok(Some(node_bytes)) = node_rx.recv_timeout(SYNC_FETCH_TIMEOUT) else {
            continue;
        };
        match cc.insert_node(&cid, &node_bytes) {
            Ok(true) => inserted_any = true,
            Ok(false) => {}
            Err(e) => {
                warn!(error = %e, "sync: node from peer rejected");
                continue;
            }
        }
        // Walk children so the BFS keeps going.
        if let Some(node) = DagNode::<crate::commit::Blake2b, CrdtEvent>::from_bytes(&node_bytes) {
            for child in node.children {
                frontier.push(child.0);
            }
        }
    }

    if inserted_any {
        cc.compact_roots()?;
    }
    Ok(SyncOutcome::PeerHasGroup {
        inserted: inserted_any,
    })
}

/// Shared "last activity" instant, bumped on every dispatch. The
/// node uses it as a global idle signal that — unlike outbox-only
/// monitoring — also accounts for invoke traffic, which doesn't
/// flow through the outbox.
type ActivityClock = Arc<Mutex<Instant>>;

impl VosNode {
    /// Create a node with the default prefix (0 = local/unscoped).
    pub fn new() -> Self {
        Self::with_prefix(0)
    }

    /// Create a node with a specific network prefix.
    pub fn with_prefix(node_prefix: u16) -> Self {
        let (outbox_tx, outbox_rx) = mpsc::channel();
        Self {
            node_prefix,
            next_local: AtomicU16::new(1), // 0 is reserved for registry
            routes: HashMap::new(),
            agents: Vec::new(),
            outbox_tx,
            outbox_rx,
            invoke_routes: Arc::new(Mutex::new(HashMap::new())),
            agent_names: Arc::new(std::sync::RwLock::new(HashMap::new())),
            shutdown: Arc::new(AtomicBool::new(false)),
            agent_shutdown: Arc::new(Mutex::new(HashMap::new())),
            agent_info: Arc::new(std::sync::RwLock::new(HashMap::new())),
            last_activity: Arc::new(Mutex::new(Instant::now())),
            #[cfg(feature = "network")]
            shared_network: Arc::new(Mutex::new(None)),
            #[cfg(feature = "network")]
            operator_peer: None,
            operator_signer: None,
            #[cfg(all(feature = "network", feature = "storage"))]
            crdt_replicas: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(all(feature = "network", feature = "storage"))]
            raft_hosts: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(feature = "network")]
            manifest: Arc::new(OnceLock::new()),
            #[cfg(all(feature = "network", feature = "storage"))]
            sync_threads: Vec::new(),
            proof_blobs: Arc::new(RwLock::new(HashMap::new())),
            proof_blobs_dir: None,
        }
    }

    /// Enable on-disk persistence for the proof-blob CAS at the
    /// given directory. Blobs `put` after this call write through
    /// to `{dir}/{hex_hash}`; on a hot-cache miss, `get` lazy-loads
    /// from disk before returning `None`. The directory is created
    /// if missing.
    ///
    /// Call this before driving any proof traffic so the disk shape
    /// is consistent across put / get. Re-calling overrides the
    /// previous directory; the in-memory hot cache is unaffected.
    pub fn with_proof_blobs_dir(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        let dir = dir.into();
        let _ = std::fs::create_dir_all(&dir);
        self.proof_blobs_dir = Some(dir);
        self
    }

    /// Insert `bytes` into the proof-blob store. Returns the
    /// content address (32-byte blake2b-256 of the bytes under the
    /// `"vos/proof-blob/v1"` domain tag).
    ///
    /// Idempotent on equal bytes; the hash is collision-resistant.
    /// Used by producers to stash a STARK proof before sending a
    /// message whose proof-reference field carries the returned hash.
    ///
    /// When [`proof_blobs_dir`](Self::with_proof_blobs_dir) is set,
    /// also writes the bytes to `{dir}/{hex_hash}`. Disk errors are
    /// logged at `warn!` and ignored — the hot cache still has the
    /// blob, so the local node stays functional; only persistence
    /// across restarts is lost on a disk failure.
    pub fn put_proof_blob(&self, bytes: Vec<u8>) -> [u8; 32] {
        let hash = proof_blob_hash(&bytes);
        if let Some(dir) = &self.proof_blobs_dir {
            let path = dir.join(proof_blob_filename(&hash));
            if !path.exists()
                && let Err(e) = std::fs::write(&path, &bytes)
            {
                warn!(error = %e, path = %path.display(), "proof_blobs: disk write failed");
            }
        }
        if let Ok(mut store) = self.proof_blobs.write() {
            store.insert(hash, bytes);
        }
        hash
    }

    /// Look up a proof blob by hash. Returns `None` when neither
    /// the hot cache nor disk (if configured) holds the blob.
    /// Cross-node fetch (cycle A1+A2) layers on top of this; a
    /// successful network fan-out caches into both tiers.
    pub fn get_proof_blob(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        if let Some(bytes) = self.proof_blobs.read().ok()?.get(hash).cloned() {
            return Some(bytes);
        }
        // Hot-cache miss: try disk if we have a backing directory.
        let dir = self.proof_blobs_dir.as_ref()?;
        let path = dir.join(proof_blob_filename(hash));
        let bytes = std::fs::read(&path).ok()?;
        // Hydrate the hot cache so the next lookup is fast.
        if let Ok(mut store) = self.proof_blobs.write() {
            store.insert(*hash, bytes.clone());
        }
        Some(bytes)
    }

    /// Pre-populate the manifest payload exposed to peers via
    /// `Frame::ManifestReq`. Set-once: a second call is a
    /// programming error and is silently ignored. Call before
    /// [`attach_network`](Self::attach_network) — the
    /// `NetworkService` snapshot taken there reads from this slot.
    /// `vosx space up` calls this with the parsed `space.toml` bytes
    /// plus every actor blob so `vosx space join`ers can fetch the
    /// cluster's manifest without `--manifest`.
    #[cfg(feature = "network")]
    pub fn set_manifest(&self, reply: crate::network::ManifestReply) {
        let _ = self.manifest.set(reply);
    }

    /// Record this daemon's operator — the PeerId bytes of the CLI identity
    /// that started it (`vosx space up` loads the operator's
    /// `vosx/identity.key`). The value is threaded into the [`NodeService`]
    /// at [`attach_network`](Self::attach_network), where the locality gate
    /// admits this caller — and only this caller — to a node-confined agent.
    /// Call before `attach_network`; afterwards the service holds its own
    /// copy.
    #[cfg(feature = "network")]
    pub fn set_operator_peer(&mut self, peer_bytes: Vec<u8>) {
        self.operator_peer = Some(peer_bytes);
    }

    /// This daemon's operator PeerId bytes (the identity that ran `vosx
    /// space up`), if one was recorded. Lets boot-time reconcile tell
    /// "I am the space admin" (operator == registry root / has an ADMIN
    /// grant) from "I am a non-admin joiner", so a catalog op refused
    /// because the signer can't author isn't misread as the benign
    /// awaiting-sync case.
    #[cfg(feature = "network")]
    pub fn operator_peer(&self) -> Option<&[u8]> {
        self.operator_peer.as_deref()
    }

    /// Install the operator's catalog-op signer (the "sign on relay"
    /// seam). `signer` produces the packed `auth` blob for a registry
    /// op's canonical bytes; the space-registry agent thread calls it to
    /// author-sign `install`/`publish`/`upgrade`/`uninstall`/`unpublish`
    /// before recording, so a keyless PVM agent's or the in-process
    /// reconcile's catalog mutation authorizes on the operator's node.
    /// Must be set before the registry agent is registered so its thread
    /// captures the signer. Unset (the default) leaves catalog ops
    /// unsigned — the registry then refuses them (fail closed).
    pub fn set_operator_signer<F>(&mut self, signer: F)
    where
        F: Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        self.operator_signer = Some(Arc::new(signer));
    }

    /// Attach a libp2p [`Network`](crate::network::Network) so the
    /// node can route to and from peers.
    ///
    /// After this call:
    /// - [`route`](Self::route) forwards any envelope whose target
    ///   `node_prefix` doesn't match this node over the wire (via
    ///   the network's `peer_for_prefix` lookup).
    /// - A bridge thread reads inbound `Tell` frames from the
    ///   network and feeds them back into this node's outbox, so
    ///   they're routed by the same path local-only traffic uses.
    ///
    /// The bridge thread exits cleanly when either the network's
    /// inbox closes (because the [`Network`](crate::network::Network)
    /// is dropping) or the outbox closes (because the node is
    /// being collected).
    #[cfg(feature = "network")]
    pub fn attach_network(&mut self, network: crate::network::Network) {
        // Install the unified service first so any inbound frame
        // that arrives between now and the bridge starting gets
        // resolved against this node's tables (invoke_routes,
        // crdt_replicas, host-supplied manifest) rather than the
        // trait's empty-reply defaults.
        let service = Arc::new(NodeService {
            invoke_routes: self.invoke_routes.clone(),
            agent_names: self.agent_names.clone(),
            agent_shutdown: self.agent_shutdown.clone(),
            agent_info: self.agent_info.clone(),
            #[cfg(feature = "storage")]
            replicas: self.crdt_replicas.clone(),
            manifest: self.manifest.clone(),
            proof_blobs: self.proof_blobs.clone(),
            proof_blobs_dir: self.proof_blobs_dir.clone(),
            operator_peer: self.operator_peer.clone(),
            #[cfg(feature = "storage")]
            sync_floor_cache: Arc::new(RwLock::new(HashMap::new())),
        });
        network.set_service(service);

        let inbox_rx = match network.take_inbox() {
            Some(rx) => rx,
            None => {
                warn!("network already had its inbox taken; bridge will not run");
                *self.shared_network.lock().unwrap() = Some(Arc::new(network));
                return;
            }
        };

        let outbox_tx = self.outbox_tx.clone();
        let activity = self.last_activity.clone();
        let shutdown = self.shutdown.clone();
        thread::spawn(move || {
            for tell in inbox_rx {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                *activity.lock().unwrap() = Instant::now();
                let env = Envelope {
                    from: ServiceId(tell.from),
                    to: ServiceId(tell.to),
                    payload: tell.payload,
                };
                if outbox_tx.send(env).is_err() {
                    break;
                }
            }
        });

        *self.shared_network.lock().unwrap() = Some(Arc::new(network));
    }

    /// Allocate the next service ID on this node.
    fn alloc_id(&self) -> ServiceId {
        let local = self.next_local.fetch_add(1, Ordering::Relaxed);
        ServiceId::new(self.node_prefix, local)
    }

    /// Record an installed instance name in the [`AgentNames`] reverse
    /// map under its local id. Called by both `register_inner` and
    /// `register_extension_inner` so every registered service is
    /// resolvable name-from-id by the auth path.
    ///
    /// The well-known `space-registry` name is filled in for the
    /// registry's fixed id even when the caller passed no name (vosx
    /// registers the registry from a bare `AgentConfig`), so the gate
    /// resolves the registry through the map uniformly instead of via a
    /// hardcoded special case. A WARN fires when an insert would
    /// overwrite a *different* existing name — a `local_id` collision in
    /// the ~15-bit instance space (`instance_service_id` masks to
    /// `0x100..=0x7FFF`); last-writer-wins, matching the registry's own
    /// id derivation.
    fn record_agent_name(&self, id: ServiceId, name: Option<String>) {
        let local = local_id_of(id.0);
        let name = name.or_else(|| {
            (local == ServiceId::REGISTRY.local_id()).then(|| REGISTRY_AGENT_NAME.to_string())
        });
        let Some(name) = name else { return };
        let Ok(mut map) = self.agent_names.write() else {
            return;
        };
        if let Some(prev) = map.get(&local) {
            if prev != &name {
                warn!(
                    local_id = local,
                    previous = %prev,
                    new = %name,
                    "register: instance-name collision on local id; \
                     auth reverse-lookup will use the latest name"
                );
            }
        }
        map.insert(local, name);
    }

    /// Resolve a (possibly prefix-scoped) `ServiceId` value back to the
    /// installed instance name registered for it, if any. The public
    /// reverse lookup backing actor-local grant probes and `intra_caps`
    /// targeting. Returns `None` for ids this node never registered
    /// (anonymous agents, cross-node targets the gate doesn't run for).
    pub fn agent_name_for(&self, svc_id: u32) -> Option<String> {
        self.agent_names
            .read()
            .ok()?
            .get(&local_id_of(svc_id))
            .cloned()
    }

    /// Register an agent at an explicit `ServiceId` instead of
    /// auto-allocating one. Used for well-known slots like the
    /// hyperspace registry which always lives at
    /// [`ServiceId::REGISTRY`] (== `ServiceId(0)`) so any agent
    /// can address it by a stable id without a name lookup.
    ///
    /// Caller is responsible for not double-registering.
    pub fn register_at_id(&mut self, config: AgentConfig, id: ServiceId) -> ServiceId {
        self.register_inner(config, id)
    }

    /// Register an agent and return its service ID.
    /// The agent starts immediately on a new thread.
    pub fn register(&mut self, config: AgentConfig) -> ServiceId {
        let id = self.alloc_id();
        self.register_inner(config, id)
    }

    // `config` is mutated only on the CRDT/Raft pre-open path (gated
    // all(storage, network)); without both, the `mut` is unused.
    #[cfg_attr(not(all(feature = "storage", feature = "network")), allow(unused_mut))]
    fn register_inner(&mut self, mut config: AgentConfig, id: ServiceId) -> ServiceId {
        let (tx, rx) = mpsc::channel();
        let (invoke_tx, invoke_rx) = mpsc::channel();
        let outbox = self.outbox_tx.clone();

        self.routes.insert(id.0, tx);
        self.invoke_routes.lock().unwrap().insert(id.0, invoke_tx);
        self.record_agent_name(id, config.name.clone());
        // Monotone locality seal (immutable-local): a named agent's
        // shareability may only ever narrow, never widen — enforced
        // host-side, ahead of the sync-attach branches below, because the
        // registry row that carries `consistency` is replicated and not
        // trusted.
        #[cfg(feature = "storage")]
        config.apply_consistency_seal(id);
        // Actor-mode agent: kind 0, no serve endpoint. Backs `__describe`.
        // `consistency` is recorded *after* the seal so the locality gate
        // sees the effective (possibly narrowed) tier, never a forged
        // registry row's requested one.
        self.agent_info.write().unwrap().insert(
            id.0,
            AgentInfo {
                name: config.name.clone(),
                kind: crate::extension::ExtensionKind::Actor as u8,
                serves_addr: None,
                consistency: Some(config.consistency),
                network_reachable: config.network_reachable,
            },
        );

        // Pre-open the redb database for CRDT actors that declare
        // a replication group, so the same `Arc<Database>` powers
        // both the agent's `CrdtCommit` and the network's
        // `SyncHandler`. redb is exclusive on file open, so this
        // is the only way to share the file across threads.
        //
        // When the file opens cleanly we also create a one-shot-
        // style notification channel: the per-replica sync ticker
        // pings the Sender after a non-empty merge, the agent
        // thread holds the Receiver and runs `soft_restart_crdt`
        // between dispatches to refresh its in-memory state.
        #[cfg(all(feature = "network", feature = "storage"))]
        let sync_rx: Option<mpsc::Receiver<()>> = if config.consistency == Consistency::Crdt {
            config.replication_id.and_then(|rep_id| {
                let path = config.db_path(id)?;
                match redb::Database::create(&path) {
                    Ok(db) => {
                        let slot = ReplicaSlot {
                            db: Arc::new(db),
                            commit_lock: Arc::new(Mutex::new(())),
                            name: config.name.clone().unwrap_or_default(),
                            node_validator: config.node_validator.clone(),
                        };
                        self.crdt_replicas
                            .lock()
                            .unwrap()
                            .insert(rep_id, slot.clone());
                        config.pre_opened_db = Some(slot.db.clone());
                        config.pre_opened_lock = Some(slot.commit_lock.clone());
                        let (sync_tx, sync_rx) = mpsc::channel::<()>();
                        self.spawn_sync_thread(rep_id, slot, Some(sync_tx));
                        Some(sync_rx)
                    }
                    Err(e) => {
                        error!(%id, error = %e, "register: failed to open CRDT db; \
                            replication will be inactive");
                        None
                    }
                }
            })
        } else if config.consistency == Consistency::Raft && !config.members.is_empty() {
            // Multi-mode Raft: spawn a worker, install it as the
            // network's RaftRpcHandler, and bridge the worker's
            // apply notifications into both (a) the agent's
            // sync_rx (so the soft-restart path catches up state
            // on followers) and (b) the strategy's apply_rx (so
            // the leader's commit_with_log unblocks once its
            // proposed entry commits).
            //
            // A single-element member list is the solo-bootstrap
            // case: the worker self-elects with a quorum of one
            // and can then admit joiners through `RaftJoinReq` —
            // unlike the memberless fallback below, which never
            // answers cluster RPCs. The persisted active config,
            // when present, supersedes `config.members` on boot.
            let network = self.shared_network.lock().ok().and_then(|g| g.clone());
            let rep_id = config.replication_id.unwrap_or([0u8; 32]);
            match config.db_path(id).map(|p| {
                let db = redb::Database::create(&p);
                (p, db)
            }) {
                Some((_path, Ok(db))) => {
                    let db = Arc::new(db);
                    config.pre_opened_db = Some(db.clone());

                    let worker_cfg = crate::raft::WorkerConfig {
                        me: id.node_prefix(),
                        members: config.members.clone(),
                        replication_id: rep_id,
                        election_timeout_ms: (150, 300),
                        heartbeat_interval_ms: 50,
                    };
                    let (worker_tx, worker_rx) = mpsc::channel::<u64>();
                    let worker = crate::raft::RaftWorker::spawn(
                        db.clone(),
                        worker_cfg,
                        network.clone(),
                        Some(worker_tx),
                    );
                    if let Some(net) = network.as_ref() {
                        net.register_raft_handler(rep_id, Arc::new(worker.handler()));
                    }
                    // Relay: each commit advance fans out to both
                    // the strategy's apply_rx and the agent's
                    // sync_rx. Lives until the worker drops its
                    // sender (either side closing is fine).
                    let (commit_tx, commit_rx) = mpsc::channel::<u64>();
                    let (sync_tx, sync_rx) = mpsc::channel::<()>();
                    thread::Builder::new()
                        .name(format!("raft-relay-{:08x}", id.0))
                        .spawn(move || {
                            while let Ok(idx) = worker_rx.recv() {
                                let _ = commit_tx.send(idx);
                                let _ = sync_tx.send(());
                            }
                        })
                        .expect("spawn raft relay");
                    config.raft_worker = Some(worker);
                    config.raft_apply_rx = Some(commit_rx);
                    // Record the group membership so the extension
                    // ask path can forward follower-rejected writes
                    // to the leader (see `RaftFwd` / `route_invoke`).
                    self.raft_hosts.lock().unwrap().insert(id.0, rep_id);
                    Some(sync_rx)
                }
                Some((path, Err(e))) => {
                    error!(%id, path = %path.display(), error = %e,
                        "register: failed to open Raft db; replication will be inactive");
                    None
                }
                None => None,
            }
        } else {
            None
        };

        let invoke_routes = self.invoke_routes.clone();
        // This agent polls its OWN shutdown flag (a node-wide
        // shutdown fans out to it), so the daemon can stop it individually.
        let shutdown = self.register_agent_shutdown(id);
        let activity = self.last_activity.clone();
        // Reverse svc-id → instance-name map, so an agent that opts into
        // bounded outbound relay (declared `intra_caps`) can resolve each
        // invoke target's name to pick its cap ceiling.
        let agent_names = self.agent_names.clone();
        #[cfg(feature = "network")]
        let shared_network = self.shared_network.clone();
        // Leader-forward plan for an agent that opted into bounded relay and
        // writes to a raft target: a follower that refuses the write (drops the
        // reply) is recognized + the write re-sent to the leader (mirrors the
        // extension ask path's `route_invoke`).
        let raft_fwd = RaftFwd {
            #[cfg(all(feature = "network", feature = "storage"))]
            network: self.shared_network.clone(),
            #[cfg(all(feature = "network", feature = "storage"))]
            hosts: self.raft_hosts.clone(),
        };
        // Only the space-registry (local id 0) author-signs catalog
        // mutations on relay; no other agent holds the operator key.
        // Excludes the hyperspace registry (local id 1), whose
        // register_remote has a separate trust model.
        let operator_signer = if id.local_id() == ServiceId::REGISTRY.local_id() {
            self.operator_signer.clone()
        } else {
            None
        };

        let join = thread::spawn(move || {
            agent_thread(
                id,
                config,
                rx,
                invoke_rx,
                outbox,
                invoke_routes,
                agent_names,
                raft_fwd,
                shutdown,
                activity,
                operator_signer,
                #[cfg(feature = "network")]
                shared_network,
                #[cfg(all(feature = "network", feature = "storage"))]
                sync_rx,
            )
        });

        self.agents.push(AgentHandle { join: Some(join) });
        id
    }

    /// Register a native extension at a freshly-allocated
    /// ServiceId. Spawns the extension thread immediately.
    pub fn register_extension(&mut self, config: ExtensionConfig) -> ServiceId {
        let id = self.alloc_id();
        self.register_extension_inner(config, id)
    }

    /// Register an extension at an explicit `ServiceId`. Mirrors
    /// [`register_at_id`](Self::register_at_id) for the actor side
    /// — used to slot a mock registry into `ServiceId::REGISTRY`
    /// (= 0) for tests and to install built-in service extensions
    /// at well-known ids.
    ///
    /// Caller is responsible for not double-registering.
    pub fn register_extension_at_id(
        &mut self,
        config: ExtensionConfig,
        id: ServiceId,
    ) -> ServiceId {
        self.register_extension_inner(config, id)
    }

    fn register_extension_inner(&mut self, config: ExtensionConfig, id: ServiceId) -> ServiceId {
        let (tx, rx) = mpsc::channel();
        let (invoke_tx, invoke_rx) = mpsc::channel();
        let outbox = self.outbox_tx.clone();

        self.routes.insert(id.0, tx);
        self.invoke_routes.lock().unwrap().insert(id.0, invoke_tx);
        self.record_agent_name(id, config.name.clone());
        // A serving (transport) extension carries a host-bound listen
        // endpoint; otherwise it's an actor-mode extension. We can't cheaply read the exact `.so`
        // kind here without a second dlopen, so derive transport-vs-actor from
        // whether the host was asked to serve. Backs the `__describe` primitive.
        self.agent_info.write().unwrap().insert(
            id.0,
            AgentInfo {
                name: config.name.clone(),
                kind: if config.serves_addr.is_some() {
                    crate::extension::ExtensionKind::Transport as u8
                } else {
                    crate::extension::ExtensionKind::Actor as u8
                },
                serves_addr: config.serves_addr.clone(),
                // Native extensions have no consistency tier; they relay
                // through their own caps model and stay network-reachable.
                consistency: None,
                network_reachable: true,
            },
        );

        // Per-agent shutdown flag (node-wide shutdown fans out to
        // it) so the daemon can stop this extension individually — the generic
        // primitive replacing the gateway's bespoke `inner.stop`.
        let shutdown = self.register_agent_shutdown(id);
        let activity = self.last_activity.clone();
        let invoke_routes = self.invoke_routes.clone();
        let agent_names = self.agent_names.clone();
        let proof_blobs = self.proof_blobs.clone();
        let proof_blobs_dir = self.proof_blobs_dir.clone();
        #[cfg(feature = "network")]
        let shared_network = self.shared_network.clone();
        let raft_fwd = RaftFwd {
            #[cfg(all(feature = "network", feature = "storage"))]
            network: self.shared_network.clone(),
            #[cfg(all(feature = "network", feature = "storage"))]
            hosts: self.raft_hosts.clone(),
        };

        let join = thread::spawn(move || {
            extension_thread(
                id,
                config,
                rx,
                invoke_rx,
                outbox,
                invoke_routes,
                agent_names,
                shutdown,
                activity,
                proof_blobs,
                proof_blobs_dir,
                raft_fwd,
                #[cfg(feature = "network")]
                shared_network,
            )
        });

        self.agents.push(AgentHandle { join: Some(join) });
        id
    }

    /// Route messages until the node has been globally idle for the
    /// default duration (2 seconds). Shorthand for
    /// `run_until_idle(Duration::from_secs(2))`.
    pub fn run(&mut self) {
        self.run_until_idle(Duration::from_secs(2));
    }

    /// Route messages until traffic — both outbox routing AND
    /// agent/worker dispatch — has been quiet for `threshold`,
    /// then signal shutdown to all threads.
    ///
    /// Unlike the previous "agents auto-exit on idle" heuristic,
    /// this is decided centrally: agents stay alive as long as the
    /// node hasn't told them to stop. That keeps cross-agent
    /// invoke peers reachable for the entire run, even when one
    /// side has nothing on its inbox at the moment.
    pub fn run_until_idle(&mut self, threshold: Duration) {
        *self.last_activity.lock().unwrap() = Instant::now();
        loop {
            match self.outbox_rx.recv_timeout(Duration::from_millis(50)) {
                Ok(envelope) => {
                    self.route(envelope);
                    *self.last_activity.lock().unwrap() = Instant::now();
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // If every agent has already exited (e.g.
                    // they all errored at startup), there's no
                    // point waiting out the threshold.
                    let all_done = self
                        .agents
                        .iter()
                        .all(|h| h.join.as_ref().is_none_or(|j| j.is_finished()));
                    if all_done {
                        break;
                    }

                    let idle = self.last_activity.lock().unwrap().elapsed();
                    if idle >= threshold {
                        self.signal_node_shutdown();
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    /// Run forever, only stopping when [`shutdown`](Self::shutdown)
    /// is called from another thread (e.g. a SIGTERM handler) or
    /// every agent has exited on its own.
    pub fn run_forever(&mut self) {
        self.run_forever_with(|_| {});
    }

    /// Like [`run_forever`](Self::run_forever), but invokes
    /// `on_tick` with `&mut self` on every loop pass — after each
    /// routed envelope and on each ~50 ms idle timeout — so the
    /// hook keeps firing under sustained envelope traffic. This is
    /// the only moment the embedder can get mutable access to a
    /// running node, so it's the hook for maintenance work that
    /// needs registration rights — e.g. spawning agents that were
    /// installed (or CRDT-synced into the registry) after boot.
    ///
    /// Contract:
    /// - The callback runs on the router thread with envelope
    ///   routing paused, and may fire many times per second under
    ///   traffic: rate-limit internally (a cheap elapsed check) and
    ///   keep the heavy path short.
    /// - Synchronous invokes are safe ONLY against targets whose
    ///   handlers never issue envelope-path effects: PVM actors and
    ///   `ctx.ask_dispatch` ride `invoke_routes` directly, but an
    ///   extension handler doing a plain `ctx.ask` parks its
    ///   envelope on the outbox this loop drains — invoking such a
    ///   target from here stalls all routing for the invoke
    ///   timeout and then fails.
    /// - The loop still exits when every agent thread has finished,
    ///   checked before the idle-arm callback: on a node with no
    ///   (live) agents the hook never fires, so it cannot be used
    ///   to bootstrap the first agent.
    pub fn run_forever_with(&mut self, mut on_tick: impl FnMut(&mut Self)) {
        loop {
            match self.outbox_rx.recv_timeout(Duration::from_millis(50)) {
                Ok(envelope) => {
                    self.route(envelope);
                    *self.last_activity.lock().unwrap() = Instant::now();
                    on_tick(self);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if self.shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    let all_done = self
                        .agents
                        .iter()
                        .all(|h| h.join.as_ref().is_none_or(|j| j.is_finished()));
                    if all_done {
                        break;
                    }
                    on_tick(self);
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    /// Trigger an explicit node-wide shutdown. Threads notice on their next
    /// iteration (≤ 50 ms) and exit cleanly. Safe to call from a signal handler
    /// or another thread.
    pub fn shutdown(&self) {
        self.signal_node_shutdown();
    }

    /// Set the node-wide shutdown flag AND fan it out to every per-agent flag
    ///. Agent threads poll their own flag, so the fan-out is
    /// what actually stops them on a node-wide shutdown; non-agent machinery
    /// (network bridge, sync ticker) still reads the node-wide flag directly.
    fn signal_node_shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Ok(map) = self.agent_shutdown.lock() {
            for flag in map.values() {
                flag.store(true, Ordering::Relaxed);
            }
        }
    }

    /// Allocate (and register) this agent's own shutdown flag.
    /// Returned to the spawn site as the thread's `shutdown` signal; retained in
    /// [`Self::agent_shutdown`] so [`Self::stop_agent`] / a node-wide shutdown
    /// can flip it. Idempotent per id (re-registering returns a fresh flag).
    fn register_agent_shutdown(&mut self, id: ServiceId) -> Arc<AtomicBool> {
        let flag = Arc::new(AtomicBool::new(false));
        if self
            .agent_shutdown
            .lock()
            .unwrap()
            .insert(id.0, flag.clone())
            .is_some()
        {
            // Two agents at the same full id.0 (a ~15-bit instance-name hash
            // collision under one node prefix; same root cause as the
            // `record_agent_name` collision WARN). The evicted flag is no
            // longer reachable from `signal_node_shutdown`'s fan-out, so a
            // transport agent left on the evicted flag could miss a node-wide
            // shutdown (its accept loop polls only this flag) — surface it.
            warn!(
                id = id.0,
                "register: shutdown-flag collision on service id; node-wide shutdown \
                 may not reach the evicted agent (rename one of the colliding instances)"
            );
        }
        flag
    }

    /// Stop a SINGLE agent by id without tearing down the node.
    /// Flips that agent's shutdown flag; its thread exits on the next poll
    /// (≤ 50 ms) — the generic lifecycle primitive behind `vosx <agent> stop`,
    /// uniform across actor / service / transport agents. Returns `false` when
    /// no agent is registered under `id`.
    pub fn stop_agent(&self, id: ServiceId) -> bool {
        match self
            .agent_shutdown
            .lock()
            .ok()
            .and_then(|m| m.get(&id.0).cloned())
        {
            Some(flag) => {
                flag.store(true, Ordering::Relaxed);
                true
            }
            None => false,
        }
    }

    /// Whether an agent (actor, service, or transport) is
    /// registered under `id` on this node. Stays `true` for agents
    /// that were stopped individually (`stop_agent`) — their slot
    /// is still taken, so re-registering at the same id would
    /// clobber routes. The cheap idempotency probe for embedder
    /// spawn-reconcile loops.
    pub fn has_agent(&self, id: ServiceId) -> bool {
        self.agent_info
            .read()
            .map(|m| m.contains_key(&id.0))
            .unwrap_or(false)
    }

    /// Describe a SINGLE agent by id: a JSON snapshot of its
    /// registered metadata + live running flag, backing `vosx <agent> describe`.
    /// Generic across actor / service / transport agents (the in-process twin of
    /// the `__describe` host interceptor). `None` when no agent is registered
    /// under `id`.
    pub fn describe_agent(&self, id: ServiceId) -> Option<String> {
        let info = self.agent_info.read().ok()?.get(&id.0).cloned()?;
        let running = self
            .agent_shutdown
            .lock()
            .ok()
            .and_then(|m| m.get(&id.0).map(|f| !f.load(Ordering::Relaxed)))
            .unwrap_or(true)
            && !self.shutdown.load(Ordering::Relaxed);
        Some(describe_agent_json(id.0, &info, running))
    }

    /// Clone of the attached network, if any. Lets external code
    /// (tests, monitoring, host-side bootstraps) inspect peer
    /// state — `peer_for_prefix`, `connected_peers`, etc. —
    /// without taking the network out of the node's ownership.
    /// Returns `None` until [`attach_network`](Self::attach_network)
    /// has run.
    #[cfg(feature = "network")]
    pub fn network(&self) -> Option<Arc<crate::network::Network>> {
        self.shared_network.lock().ok().and_then(|g| g.clone())
    }

    /// Clone of the shutdown signal. Set to `true` from any thread
    /// to wind the node down. Useful when the node has been moved
    /// into a [`run_forever`](Self::run_forever) thread.
    pub fn shutdown_handle(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    /// Returns a thread-safe handle that can synchronously invoke
    /// any **local** service registered on this node. Background
    /// tasks (e.g. vosx's auto-heartbeat) take this handle before
    /// [`run_forever`](Self::run_forever) blocks the main thread,
    /// then keep calling into the node from a side thread.
    ///
    /// Cross-node invokes aren't supported through this handle —
    /// it doesn't carry the network reference. Use [`invoke`](Self::invoke)
    /// from the owning thread for that.
    pub fn invoke_handle(&self) -> InvokeHandle {
        InvokeHandle {
            invoke_routes: self.invoke_routes.clone(),
            shutdown: self.shutdown.clone(),
        }
    }

    /// Clone of the outbox sender. Pushing an [`Envelope`] here
    /// runs it through [`route`](Self::route) — the same path
    /// agent threads use for outgoing transfers — so addresses
    /// targeting other nodes get forwarded over the network when
    /// one is attached. Intended for host-side bootstraps and
    /// tests that need to inject traffic from outside the agent
    /// system.
    pub fn outbox_sender(&self) -> mpsc::Sender<Envelope> {
        self.outbox_tx.clone()
    }

    /// Install a "ghost" route under a fresh ServiceId: every
    /// envelope routed to that ID is delivered to the returned
    /// channel instead of an agent. Used by integration tests to
    /// observe what crosses the routing layer; not part of the
    /// production API.
    #[cfg(test)]
    pub(crate) fn install_inspector(&mut self) -> (ServiceId, mpsc::Receiver<Envelope>) {
        let id = self.alloc_id();
        let (tx, rx) = mpsc::channel();
        self.routes.insert(id.0, tx);
        (id, rx)
    }

    /// Register a `(replication_id → redb path)` pair directly in
    /// the CRDT replica map and spin up the matching sync ticker.
    /// Used by tests that want to verify the sync layer without
    /// spinning up a real PVM agent. No notifier is wired because
    /// no agent thread is consuming.
    #[cfg(all(test, feature = "network", feature = "storage"))]
    pub(crate) fn install_test_replica(
        &mut self,
        rep_id: [u8; 32],
        db_path: &std::path::Path,
    ) -> ReplicaSlot {
        self.install_test_replica_named(rep_id, db_path, "")
    }

    /// Like [`Self::install_test_replica`] but tags the replica with an
    /// instance `name` so the sync-serve membership gate can be
    /// exercised (a `msg-*` name is private; anything else serves
    /// openly).
    #[cfg(all(test, feature = "network", feature = "storage"))]
    pub(crate) fn install_test_replica_named(
        &mut self,
        rep_id: [u8; 32],
        db_path: &std::path::Path,
        name: &str,
    ) -> ReplicaSlot {
        let slot = ReplicaSlot {
            db: Arc::new(redb::Database::create(db_path).expect("create db")),
            commit_lock: Arc::new(Mutex::new(())),
            name: name.to_string(),
            node_validator: None,
        };
        self.crdt_replicas
            .lock()
            .unwrap()
            .insert(rep_id, slot.clone());
        self.spawn_sync_thread(rep_id, slot.clone(), None);
        slot
    }

    /// Spawn the per-replica sync ticker. Detached: exits via the
    /// shared shutdown flag (set on `collect`/`shutdown`) or when
    /// the network/db Arcs die. `notifier` (when present) is
    /// pinged after a non-empty merge so the agent thread can
    /// run `soft_restart_crdt` to pick up the new state.
    #[cfg(all(feature = "network", feature = "storage"))]
    fn spawn_sync_thread(
        &mut self,
        rep_id: [u8; 32],
        slot: ReplicaSlot,
        notifier: Option<mpsc::Sender<()>>,
    ) {
        let shared_network = self.shared_network.clone();
        let shutdown = self.shutdown.clone();
        let join =
            thread::spawn(move || sync_loop(rep_id, shared_network, slot, shutdown, notifier));
        self.sync_threads.push(join);
    }

    /// Install a synchronous-invoke responder under a fresh
    /// ServiceId. The handler runs on a helper thread; each
    /// inbound `InvokeRequest` is fed its `msg` bytes and the
    /// returned `Vec<u8>` is sent back as the reply.
    #[cfg(test)]
    pub(crate) fn install_invoke_responder<F>(&mut self, mut handler: F) -> ServiceId
    where
        F: FnMut(Vec<u8>) -> Vec<u8> + Send + 'static,
    {
        let id = self.alloc_id();
        let (tx, rx) = mpsc::channel::<InvokeRequest>();
        self.invoke_routes.lock().unwrap().insert(id.0, tx);
        thread::spawn(move || {
            for req in rx {
                let reply = handler(req.msg);
                // Test responders never yield — pack as DONE so
                // the reply parses as `InvokeResult::Done` on the
                // caller side, matching real worker/agent shape.
                let envelope = encode_invoke_envelope(crate::actors::run::STATUS_DONE, &[], &reply);
                let _ = req.reply.send(envelope);
            }
        });
        id
    }

    /// Synchronously invoke a registered service from outside the
    /// PVM — for tests, host-side bootstraps, and any code path
    /// where you want to ask an agent or worker without first
    /// spinning up another PVM agent to do it.
    ///
    /// Returns the raw rkyv-encoded reply bytes, or `None` if the
    /// target isn't registered, the channel is disconnected, the
    /// reply exceeds the producer cap, or the call times out.
    /// Default timeout is 10 seconds; use
    /// [`invoke_with_timeout`](Self::invoke_with_timeout) for
    /// finer control.
    pub fn invoke(&self, target: ServiceId, msg: Vec<u8>) -> Option<Vec<u8>> {
        self.invoke_with_timeout(target, msg, Duration::from_secs(10))
    }

    /// Like [`invoke`](Self::invoke) but with an explicit timeout.
    ///
    /// Lookup order:
    ///
    /// 1. Local invoke route (any agent or worker on this node).
    /// 2. Cross-node via the attached network: when the target's
    ///    `node_prefix` doesn't match this node and a peer with
    ///    that prefix has completed the Hello handshake, the
    ///    invoke is forwarded over libp2p.
    ///
    /// Returns `None` if neither path resolves the target, or if
    /// the call times out / the channel disconnects.
    pub fn invoke_with_timeout(
        &self,
        target: ServiceId,
        msg: Vec<u8>,
        timeout: Duration,
    ) -> Option<Vec<u8>> {
        // 1. Local. Same fallback `dispatch_invoke` uses: when
        //    `target` carries this node's prefix but the agent
        //    was registered as unscoped (`ServiceId(0, local_id)`),
        //    retry with the prefix stripped. The well-known
        //    registry registers at `ServiceId::REGISTRY` (= 0),
        //    so a local invoke from an in-process Ref pointed
        //    at `(self.node_prefix, 0)` wouldn't find it
        //    otherwise.
        let local_tx = {
            let map = self.invoke_routes.lock().ok()?;
            let direct = map.get(&target.0).cloned();
            if direct.is_some() {
                direct
            } else if target.is_on_node(self.node_prefix) {
                map.get(&(target.0 & 0xFFFF)).cloned()
            } else {
                None
            }
        };
        if let Some(tx) = local_tx {
            let (reply_tx, reply_rx) = mpsc::channel();
            tx.send(InvokeRequest {
                // Host-side `VosNode::invoke` entry point.
                // `Caller::System` is the right variant for
                // embedder-originated calls (test harnesses, the
                // `vosx space up` bootstrap admin grant, etc.).
                // External peers can't synthesise this variant
                // — libp2p inbounds always arrive as
                // `Caller::Peer` via `dispatch_invoke`.
                caller: crate::actors::Caller::System,
                space_role: None,
                actor_local_role: None,
                msg,
                reply: ReplyChannel::Sync(reply_tx),
                chain: Vec::new(),
            })
            .ok()?;
            // Cross-thread channel now carries the full invoke
            // envelope (status + state + reply); host callers
            // don't care about YIELDED/DONE so unwrap to just
            // reply bytes.
            return reply_rx
                .recv_timeout(timeout)
                .ok()
                .and_then(|env| unwrap_invoke_envelope(&env));
        }

        // 2. Cross-node fallback.
        #[cfg(feature = "network")]
        {
            if !target.is_on_node(self.node_prefix) && !target.is_local() {
                let net = self.shared_network.lock().ok().and_then(|g| g.clone());
                if let Some(net) = net
                    && let Some(peer) = net.peer_for_prefix(target.node_prefix())
                {
                    // `from = 0` because this is host-side; it
                    // never participates in chain detection.
                    let reply_rx =
                        net.send_invoke(peer, ServiceId::REGISTRY.0, target.0, Vec::new(), msg);
                    // Daemon's `dispatch_invoke` already strips
                    // the envelope back to raw reply bytes, so
                    // we just forward them.
                    return reply_rx.recv_timeout(timeout).ok();
                }
            }
        }

        None
    }

    /// Route a single envelope to its destination.
    fn route(&self, envelope: Envelope) {
        let target = envelope.to;

        // Local delivery: prefix matches or target is unscoped (prefix 0)
        if target.is_on_node(self.node_prefix) || target.is_local() {
            if let Some(tx) = self.routes.get(&target.0) {
                let _ = tx.send(envelope);
            } else {
                warn!(%target, "node: no route for target, dropping");
            }
            return;
        }

        // Remote delivery via the network (if attached). The
        // target's high 16 bits select the peer; if we haven't
        // seen that prefix yet (no Hello received), the envelope
        // is dropped with a warn — VOS has no store-and-forward
        // semantics today.
        #[cfg(feature = "network")]
        {
            let net = self.shared_network.lock().ok().and_then(|g| g.clone());
            if let Some(net) = net {
                let prefix = target.node_prefix();
                if let Some(peer) = net.peer_for_prefix(prefix) {
                    net.send_tell(peer, envelope.from.0, envelope.to.0, envelope.payload);
                    return;
                }
                warn!(
                    %target,
                    prefix = format!("{prefix:#06x}"),
                    "node: no peer known for prefix; dropping remote envelope",
                );
                return;
            }
        }

        warn!(%target, "node: no network layer, dropping remote target");
    }

    /// Collect results from all agent threads. Forces shutdown if
    /// it hasn't already been requested, so callers don't have to
    /// remember the order.
    ///
    /// Also joins the per-replica sync threads. Without this,
    /// they outlive the node and keep `Arc<redb::Database>`
    /// references live, blocking any subsequent
    /// `redb::Database::create` against the same file with
    /// "Database already open. Cannot acquire lock." Restart
    /// scenarios depend on this join happening.
    pub fn collect(mut self) -> Vec<AgentResult> {
        // Fan the node-wide shutdown out to every per-agent flag
        // so agent threads polling their OWN flag — notably the transport accept
        // loop, which has no inbox to disconnect — exit cleanly.
        self.signal_node_shutdown();
        drop(self.outbox_tx);
        drop(self.routes); // drop agent inboxes so threads can detect disconnect
        // Drain the invoke routes too so threads' invoke_rx
        // disconnects when the node is winding down.
        self.invoke_routes.lock().unwrap().clear();
        drop(self.invoke_routes); // drop our reference so threads' Arc count drops

        // Drop the replica registry so the sync threads' last
        // reference to each `Arc<redb::Database>` is the one
        // they hold themselves — once they exit, the underlying
        // file is unlocked.
        #[cfg(all(feature = "network", feature = "storage"))]
        {
            self.crdt_replicas.lock().unwrap().clear();
        }

        let agent_results: Vec<AgentResult> = self
            .agents
            .iter_mut()
            .filter_map(|h| h.join.take().and_then(|j| j.join().ok()))
            .collect();

        // Sync threads poll `shutdown` every SYNC_INTERVAL and
        // exit on the next tick, so this is a bounded wait.
        #[cfg(all(feature = "network", feature = "storage"))]
        for h in self.sync_threads.drain(..) {
            let _ = h.join();
        }

        agent_results
    }
}

impl Default for VosNode {
    fn default() -> Self {
        Self::new()
    }
}

// ── Agent thread ─────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
// `config` is mutated only on the CRDT/Raft pre-open path (gated
// all(storage, network)); without both, the `mut` is unused.
#[cfg_attr(not(all(feature = "storage", feature = "network")), allow(unused_mut))]
fn agent_thread(
    id: ServiceId,
    mut config: AgentConfig,
    inbox: mpsc::Receiver<Envelope>,
    invoke_rx: mpsc::Receiver<InvokeRequest>,
    outbox: mpsc::Sender<Envelope>,
    invoke_routes: InvokeRoutes,
    agent_names: AgentNames,
    raft_fwd: RaftFwd,
    shutdown: Arc<AtomicBool>,
    activity: ActivityClock,
    operator_signer: Option<crate::registry::CatalogOpSigner>,
    #[cfg(feature = "network")] shared_network: SharedNetwork,
    #[cfg(all(feature = "network", feature = "storage"))] sync_rx: Option<mpsc::Receiver<()>>,
) -> AgentResult {
    use std::collections::VecDeque;

    let mut runtime = VosRuntime::new();
    let bump = || *activity.lock().unwrap() = Instant::now();

    // The chain of ServiceIds currently on the synchronous-invoke
    // stack leading to this thread, including this agent itself.
    // Updated at the entry of every dispatch and read by the
    // `external_invoke` closure to short-circuit cycles and cap
    // total depth. Wrapped in Arc<Mutex<...>> rather than
    // Rc<RefCell<...>> so the closure satisfies the `Send` bound
    // on `ExternalInvokeFn`.
    let current_chain: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));

    // External invoke handler for ctx.ask targets that live on a
    // different thread (workers OR other agents). Looks up the
    // target's invoke channel in the shared route table and
    // blocks on the reply, with two safety checks first:
    //
    //   - Cycle: if `target` already appears in the current chain,
    //     forwarding would deadlock. Abort with `None`, which
    //     surfaces to the caller's PVM as `InvokeError::NotFound`.
    //   - Depth: cap at MAX_CROSS_AGENT_DEPTH hops. Same abort.
    let invoke_routes_for_ext = invoke_routes.clone();
    let chain_for_ext = current_chain.clone();
    // For an agent that opted into bounded outbound relay (declared
    // `intra_caps`), the closure resolves each target's name + relays the real
    // caller capped per cap. Empty caps (the default) keep the legacy trusted
    // `Caller::Actor` relay that every existing agent→agent call relies on.
    let agent_names_for_ext = agent_names.clone();
    let intra_caps_for_ext = config.intra_caps.clone();
    #[cfg(feature = "network")]
    let shared_network_for_ext = shared_network.clone();
    // Only the cross-node routing branch (network) reads this.
    #[cfg(feature = "network")]
    let local_prefix = id.node_prefix();
    runtime.set_external_invoke(Box::new(move |target, msg| {
        let chain_snapshot = chain_for_ext.lock().ok()?.clone();

        match check_invoke_forward(&chain_snapshot, target.0) {
            InvokeForwardCheck::Allowed => {}
            InvokeForwardCheck::Cycle => {
                warn!(
                    target = target.0,
                    chain = ?chain_snapshot,
                    "cross-agent invoke would form a cycle; aborting forward",
                );
                return None;
            }
            InvokeForwardCheck::DepthExceeded => {
                warn!(
                    depth = chain_snapshot.len(),
                    cap = MAX_CROSS_AGENT_DEPTH,
                    "cross-agent invoke chain exceeded depth cap; aborting forward",
                );
                return None;
            }
        }

        // 1. Local invoke route — same node, agent or worker.
        let local_tx = {
            let map = invoke_routes_for_ext.lock().ok()?;
            map.get(&target.0).cloned()
        };
        if let Some(tx) = local_tx {
            // Caller for the relayed invoke. Default (no declared
            // `intra_caps`): the trusted `Caller::Actor` — `id` is the
            // calling agent's ServiceId, and being past the libp2p gate it
            // bypasses role checks (the legacy behaviour every existing
            // agent→agent call relies on). With `intra_caps` declared: bounded
            // relay of the real inbound caller (read from this thread's
            // `RELAY_CALLER`, stamped around the invoke dispatch), capped by the
            // cap for this target — exactly the extension relay model, so a
            // privileged downstream call needs a privileged original caller.
            let (caller, space_role, actor_local_role) = if intra_caps_for_ext.is_empty() {
                (crate::actors::Caller::Actor(id), None, None)
            } else {
                let target_name = agent_names_for_ext
                    .read()
                    .ok()
                    .and_then(|m| m.get(&local_id_of(target.0)).cloned());
                let propagated = current_relay_caller();
                #[allow(unused_mut)]
                let (mut caller, space_role) = resolve_relay_caller(
                    propagated.as_ref(),
                    &intra_caps_for_ext,
                    target_name.as_deref(),
                );
                // Faithfully relay the caller's actor-local grant on the final
                // target (uncapped — the cap only gates whether the relay may
                // reach it). Overrides space_role, so the carrier must stay the
                // Peer. Peer-only (libp2p gate), so `network`-gated.
                #[cfg(feature = "network")]
                let actor_local_role = match relay_actor_local_role(
                    &invoke_routes_for_ext,
                    propagated.as_ref(),
                    &intra_caps_for_ext,
                    target_name.as_deref(),
                ) {
                    Some((peer_bytes, role)) => {
                        caller = crate::actors::Caller::Peer(peer_bytes);
                        Some(role)
                    }
                    None => None,
                };
                #[cfg(not(feature = "network"))]
                let actor_local_role: Option<u8> = None;
                (caller, space_role, actor_local_role)
            };
            let (reply_tx, reply_rx) = mpsc::channel();
            tx.send(InvokeRequest {
                caller,
                space_role,
                actor_local_role,
                msg: msg.to_vec(),
                reply: ReplyChannel::Sync(reply_tx),
                chain: chain_snapshot,
            })
            .ok()?;
            // The receiver replies with the full invoke envelope;
            // unpack it back to (status, state, reply) so the
            // runtime can repack into the local invoke wire format
            // — preserving STATUS_YIELDED across the thread
            // boundary so the calling actor can keep driving a
            // yielded child.
            match reply_rx.recv_timeout(std::time::Duration::from_secs(10)) {
                Ok(envelope) => return decode_invoke_envelope(&envelope),
                // The local target dropped its reply sender — the signature of
                // a raft follower refusing a write. If it is a raft agent,
                // forward the write to the leader (the agent analogue of the
                // extension ask path's `route_invoke` leader-forward).
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    #[cfg(all(feature = "network", feature = "storage"))]
                    if let Some(rep_id) = raft_forward_plan(&raft_fwd, id, target.0) {
                        return agent_forward_to_raft_leader(
                            &raft_fwd,
                            id,
                            target.0,
                            rep_id,
                            msg.to_vec(),
                        )
                        .map(crate::runtime::ExternalInvokeReply::Done);
                    }
                    return None;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => return None,
            }
        }

        // 2. Cross-node invoke — target on a different node and we
        //    have a `Network` attached. Reuses the chain so the
        //    far side detects cycles that span multiple hosts.
        //
        // The libp2p protocol still ships only reply bytes (no
        // YIELDED/state plumbing across the wire yet), so we wrap
        // them in a DONE envelope here. A future protocol bump
        // can carry the full envelope so cross-node yielded
        // children are drivable too.
        #[cfg(feature = "network")]
        {
            if !target.is_on_node(local_prefix) && !target.is_local() {
                let net = shared_network_for_ext.lock().ok().and_then(|g| g.clone());
                if let Some(net) = net {
                    let prefix = target.node_prefix();
                    if let Some(peer) = net.peer_for_prefix(prefix) {
                        let reply_rx =
                            net.send_invoke(peer, id.0, target.0, chain_snapshot, msg.to_vec());
                        return reply_rx
                            .recv_timeout(std::time::Duration::from_secs(10))
                            .ok()
                            .map(crate::runtime::ExternalInvokeReply::Done);
                    }
                }
            }
        }

        None
    }));

    let consistency = config.consistency;
    // Recording captures the per-dispatch `EffectLog` payload the
    // strategy needs to replay deterministically on cold start.
    // Both replicating strategies want it; the non-replicating ones
    // ignore the log if handed.
    let recording_enabled = matches!(consistency, Consistency::Crdt | Consistency::Raft,);
    // Capture rep_id up front — config is consumed below.
    #[cfg(all(feature = "network", feature = "storage"))]
    let agent_rep_id: Option<[u8; 32]> = config.replication_id;
    // Multi-mode Raft: register() pre-spawned the worker and
    // handed it to us through the config; build the Multi-flavour
    // strategy here while we still own `config` mutably.
    #[cfg(all(feature = "network", feature = "storage"))]
    let raft_multi: Option<Box<dyn crate::commit::CommitStrategy>> =
        if consistency == Consistency::Raft && config.raft_worker.is_some() {
            let db = config.pre_opened_db.clone();
            let worker = config.raft_worker.take();
            let apply_rx = config.raft_apply_rx.take();
            match (db, worker, apply_rx) {
                (Some(db), Some(worker), Some(apply_rx)) => {
                    let cfg = crate::raft::RaftConfig {
                        me: id.node_prefix(),
                        members: config.members.clone(),
                        replication_id: agent_rep_id.unwrap_or([0u8; 32]),
                        ..crate::raft::RaftConfig::default()
                    };
                    match crate::raft::RaftCommit::from_worker(db, cfg, worker, apply_rx) {
                        Ok(s) => Some(Box::new(s) as Box<dyn crate::commit::CommitStrategy>),
                        Err(e) => {
                            error!(%id, error = %e, "raft multi: failed to construct strategy");
                            None
                        }
                    }
                }
                _ => None,
            }
        } else {
            None
        };
    #[cfg(not(all(feature = "network", feature = "storage")))]
    let raft_multi: Option<Box<dyn crate::commit::CommitStrategy>> = None;
    let mut strategy: Box<dyn crate::commit::CommitStrategy> = match raft_multi {
        Some(s) => s,
        None => match build_agent_strategy(&config, id, id.node_prefix()) {
            Ok(s) => s,
            Err(e) => {
                let err = format!("strategy build failed: {e}");
                error!(%id, "{err}");
                return AgentResult {
                    id,
                    panics: 0,
                    error: Some(err),
                };
            }
        },
    };

    let blob_idx = runtime.register_service_blob(config.blob);
    let svc_id = runtime.register_service_with_id(blob_idx, id);

    for (key, value) in &config.storage {
        runtime.storage.write(svc_id, key, value);
    }

    // Restore state or rebuild from the DAG.
    if let Some(state_bytes) = strategy.restore() {
        runtime
            .storage
            .write(svc_id, crate::lifecycle::STATE_KEY_BYTES, &state_bytes);
        // Rehydrate the rest of the agent's keyspace — the non-STATE
        // rows previous deltas persisted.
        match strategy.restore_writes() {
            Ok(rows) => {
                for (key, value) in rows {
                    runtime.storage.write(svc_id, &key, &value);
                }
            }
            Err(e) => warn!(%id, error = %e, "agent: restoring non-state rows failed"),
        }
        info!(%id, bytes = state_bytes.len(), "agent: restored state");
    } else if recording_enabled {
        // Cold-start replay: pull every log out of the DAG and
        // feed it through `begin_replay` / `finish_replay`. Same
        // helper we use for mid-flight soft restarts.
        match strategy.replay_logs() {
            Ok(logs) if !logs.is_empty() => {
                info!(%id, dag_nodes = logs.len(), "agent: rebuilding state from DAG");
                if let Err(err) = replay_dag_into_runtime(&mut runtime, svc_id, strategy.as_ref()) {
                    error!(%id, "{err}");
                    return AgentResult {
                        id,
                        panics: runtime.panics,
                        error: Some(err),
                    };
                }
                let _ = logs;
                // Materialize the state AND the rebuilt keyspace into
                // the strategy so subsequent cold starts hit the fast
                // path — restore_writes must return what replay just
                // produced, not whatever earlier deltas persisted. This
                // slate was seeded with every config.storage row (not
                // just INIT_KEY), so exclude them all.
                let state = runtime
                    .storage
                    .read(svc_id, crate::lifecycle::STATE_KEY_BYTES)
                    .map(|v| v.to_vec())
                    .unwrap_or_default();
                let host_seeded: Vec<&[u8]> = config
                    .storage
                    .iter()
                    .map(|(key, _)| key.as_slice())
                    .collect();
                if !state.is_empty()
                    && let Err(e) =
                        strategy.commit_rebuilt(&state, &rebuilt_rows(&runtime, svc_id, &host_seeded))
                {
                    let err = format!("post-replay commit failed: {e}");
                    error!(%id, "{err}");
                    return AgentResult {
                        id,
                        panics: runtime.panics,
                        error: Some(err),
                    };
                }
            }
            Ok(_) => {}
            Err(e) => {
                let err = format!("replay_logs failed: {e}");
                error!(%id, "{err}");
                return AgentResult {
                    id,
                    panics: runtime.panics,
                    error: Some(err),
                };
            }
        }
    }

    // Queue initial payloads. When no init payloads are supplied we
    // still kick the actor with an empty envelope so `on_start`
    // fires — matches the pre-refactor behaviour. On a Raft
    // follower the commit_with_log triggered by on_start will
    // return NotLeader, and the inbox-loop's commit-fail handler
    // soft-restarts the runtime to bring it back in sync.
    let mut pending: VecDeque<Vec<u8>> = config.init_payloads.into_iter().collect();
    if pending.is_empty() {
        pending.push_back(Vec::new());
    }

    let mut fatal_error: Option<String> = None;

    // Periodic `tick()` (when the agent declared `tick_ms`). The thread
    // synthesizes a `tick` message about every interval, between inbound
    // work — the same heartbeat the `.so` extension gets. Re-armed from
    // *now* after each fire so a slow tick doesn't build up a burst.
    let tick_interval = config.tick_ms.map(Duration::from_millis);
    let mut tick_deadline = tick_interval.map(|iv| Instant::now() + iv);

    // Loop until the node tells us to stop (or our channels
    // disconnect, which happens during collect()). No per-agent
    // idle heuristic — the node is the source of truth for "are
    // we done."
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Priority 1 — drain pending invoke requests. The caller's
        // PVM is suspended at the ecall waiting for a reply, so
        // these jump to the front of the queue.
        let mut serviced_invoke = false;
        loop {
            match invoke_rx.try_recv() {
                Ok(req) => {
                    serviced_invoke = true;
                    bump();
                    // Set the chain to the caller's chain plus our
                    // own ID, so any outgoing invokes during this
                    // dispatch see the full lineage.
                    {
                        let mut chain = current_chain.lock().unwrap();
                        chain.clear();
                        chain.extend_from_slice(&req.chain);
                        chain.push(id.0);
                    }
                    // Stamp this thread's relay caller for the duration of the
                    // dispatch, so an outbound ask during it can relay the real
                    // caller bounded by `intra_caps` (read in `external_invoke`).
                    // Only when this agent opted into bounded relay — otherwise
                    // the relay carrier is unread and the legacy `Caller::Actor`
                    // path is byte-for-byte unchanged. Cleared on scope exit
                    // (even on panic), so a refused call can't poison the next.
                    let _relay = (!config.intra_caps.is_empty()).then(|| {
                        RelayCallerGuard::stamp(PropagatedCaller {
                            caller: req.caller.clone(),
                            space_role: req.space_role,
                        })
                    });
                    let outcome = handle_invoke_request(
                        &mut runtime,
                        svc_id,
                        &outbox,
                        id,
                        req,
                        strategy.as_mut(),
                        recording_enabled,
                        operator_signer.as_ref(),
                    );
                    if let Err(e) = outcome {
                        fatal_error = Some(format!("commit failed during invoke: {e}"));
                        break;
                    }
                    #[cfg(all(feature = "network", feature = "storage"))]
                    publish_heads_if_replicated(&shared_network, agent_rep_id, strategy.as_ref());
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => break,
            }
        }
        if fatal_error.is_some() {
            break;
        }
        if serviced_invoke {
            continue;
        }

        // Cycle 4 — drain CRDT sync notifications. The per-replica
        // ticker pings us after merging remote DAG nodes; we run
        // a soft restart to reload the strategy and replay the
        // merged log set so our in-memory state matches.
        #[cfg(all(feature = "network", feature = "storage"))]
        if let Some(rx) = &sync_rx {
            let mut got_signal = false;
            while let Ok(()) = rx.try_recv() {
                got_signal = true;
            }
            // The notifier fires for every committed index, including the echo
            // of this agent's own proposals. Only reload when the backing store
            // actually gained nodes we haven't folded in (`needs_sync_reload`) —
            // soft-restarting on our own commits replays the whole DAG every
            // commit (O(n²), stalling a continuously-committing actor) and
            // transiently wipes state to genesis mid-replay.
            if got_signal && strategy.needs_sync_reload() {
                bump();
                info!(%id, "agent: CRDT sync merged new nodes; soft-restarting");
                if let Err(err) = soft_restart_crdt(&mut runtime, svc_id, strategy.as_mut()) {
                    fatal_error = Some(format!("soft restart failed: {err}"));
                    break;
                }
                // Restart the loop so we re-check invokes that
                // may have arrived during the soft restart.
                continue;
            }
        }

        let msg = if let Some(m) = pending.pop_front() {
            bump();
            // Fresh inbox-style dispatch; chain starts at us.
            *current_chain.lock().unwrap() = vec![id.0];
            m
        } else if runtime.has_work() {
            bump();
            // Residual work — pending self-messages or transfers
            // queued by the previous dispatch. A merely suspended
            // service (continuation saved, no pending message)
            // no longer counts as residual: under the dumb-host
            // model it sleeps until a parent agent invokes it
            // again. Including `is_suspended` here would busy-spin
            // on yielded children.
            // Keep the chain set by the dispatch that produced it.
            if let Err(e) = dispatch_once(
                &mut runtime,
                svc_id,
                &outbox,
                id,
                None,
                strategy.as_mut(),
                recording_enabled,
            ) {
                // On a Raft follower the commit can return
                // NotLeader. Log, soft-restart to bring the runtime
                // back in sync, continue. CRDT failures are still
                // unexpected but the same recovery applies.
                warn!(%id, error = %e, "residual-work commit failed; soft-restarting");
                #[cfg(all(feature = "network", feature = "storage"))]
                if let Err(restart_err) = soft_restart_crdt(&mut runtime, svc_id, strategy.as_mut())
                {
                    fatal_error = Some(format!("residual soft restart: {restart_err}"));
                    break;
                }
                continue;
            }
            #[cfg(all(feature = "network", feature = "storage"))]
            publish_heads_if_replicated(&shared_network, agent_rep_id, strategy.as_ref());
            continue;
        } else {
            // A due periodic tick takes priority over blocking — synthesize
            // a `tick` message and dispatch it through the normal path. No
            // inbound caller, so RELAY_CALLER stays unset (a tick's outbound
            // asks relay as Unauthenticated, matching the extension tick).
            let now = Instant::now();
            if let Some(deadline) = tick_deadline
                && now >= deadline
            {
                bump();
                *current_chain.lock().unwrap() = vec![id.0];
                tick_deadline = tick_interval.map(|iv| Instant::now() + iv);
                encode_tick_payload()
            } else {
                // Short blocking wait on inbox so we re-check the shutdown
                // flag and the invoke channel promptly, waking by the tick
                // deadline so ticks stay roughly on cadence.
                let wait = match tick_deadline {
                    Some(deadline) => deadline
                        .saturating_duration_since(now)
                        .min(Duration::from_millis(50)),
                    None => Duration::from_millis(50),
                };
                match inbox.recv_timeout(wait) {
                    Ok(env) => {
                        bump();
                        *current_chain.lock().unwrap() = vec![id.0];
                        env.payload
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        };
        if let Err(e) = dispatch_once(
            &mut runtime,
            svc_id,
            &outbox,
            id,
            Some(msg),
            strategy.as_mut(),
            recording_enabled,
        ) {
            // Tell-style dispatch on a follower will return
            // NotLeader. Soft-restart and continue rather than
            // killing the agent; the message is effectively
            // dropped (which is OK — clients should target the
            // leader).
            warn!(%id, error = %e, "tell-style commit failed; soft-restarting");
            #[cfg(all(feature = "network", feature = "storage"))]
            if let Err(restart_err) = soft_restart_crdt(&mut runtime, svc_id, strategy.as_mut()) {
                fatal_error = Some(format!("soft restart: {restart_err}"));
                break;
            }
            continue;
        }
        #[cfg(all(feature = "network", feature = "storage"))]
        publish_heads_if_replicated(&shared_network, agent_rep_id, strategy.as_ref());
    }

    if let Some(err) = &fatal_error {
        error!(%id, "{err}");
    }
    AgentResult {
        id,
        panics: runtime.panics,
        error: fatal_error,
    }
}

/// Publish the strategy's current roots on the gossipsub topic
/// for `rep_id` if the agent is replicated and a network is
/// attached. Cheap when not replicated (early return); the
/// strategy's `roots()` is also a no-op for non-CRDT types.
#[cfg(all(feature = "network", feature = "storage"))]
fn publish_heads_if_replicated(
    shared_network: &SharedNetwork,
    rep_id: Option<[u8; 32]>,
    strategy: &dyn crate::commit::CommitStrategy,
) {
    let Some(rep_id) = rep_id else {
        return;
    };
    let Some(net) = shared_network.lock().ok().and_then(|g| g.clone()) else {
        return;
    };
    let roots = strategy.roots();
    if roots.is_empty() {
        return;
    }
    net.publish_heads(rep_id, roots);
}

/// Handle a synchronous invoke request from a peer: dispatch the
/// message through this agent's runtime, capture the reply bytes
/// (rkyv-encoded `Value`), and send them back through the caller's
/// reply channel. The CALLER's `handle_invoke` wraps the reply in
/// the invoke wire frame (`[STATUS_DONE][state_len=0][reply]`) —
/// same convention workers use, so this path is symmetric with
/// `extension_thread`.
///
/// Recording is honored: a CRDT-mode agent records the dispatch
/// just like any other external message, since from its own
/// perspective the invoke IS its external event for that tick.
fn handle_invoke_request(
    runtime: &mut VosRuntime,
    svc_id: ServiceId,
    outbox: &mpsc::Sender<Envelope>,
    from_id: ServiceId,
    mut req: InvokeRequest,
    strategy: &mut dyn crate::commit::CommitStrategy,
    recording_enabled: bool,
    operator_signer: Option<&crate::registry::CatalogOpSigner>,
) -> Result<(), crate::commit::CommitError> {
    // Only the space-registry thread holds the operator signer for catalog ops.
    // If this dispatch is a signed catalog mutator, author-sign it with
    // the operator key here — at the funnel every invoke to the registry
    // converges on — and inject the `auth` blob BEFORE `begin_recording`
    // so the recorded (and thus replicated) op carries the signature.
    // The role gate + authorize_op still run inside the handler; an
    // unauthorized op mutates no state, so `write_atomic` records no DAG
    // node and nothing escapes the node. On a joined non-admin daemon
    // the signature is its own (non-admin) operator's, so authorize_op
    // refuses it and the row is consumed from sync instead.
    if let Some(signer) = operator_signer {
        if let Some(signed) = crate::registry::sign_catalog_op_on_relay(&req.msg, signer) {
            req.msg = signed;
        }
    }
    let dispatch_caller_prefix = caller_prefix_bytes(&req);
    if recording_enabled {
        runtime.begin_recording(req.msg.clone());
    }
    // Wrap the dispatch payload with a caller-info header so the PVM
    // agent can populate Context::caller and role bytes from the caller info.
    // Format: see lifecycle::TAG_CALLER_PREFIX.
    let payload = encode_caller_prefix(&req);
    send_if_deliverable(runtime, svc_id, payload);

    // Drive to quiescence, buffering external transfers as we go. The
    // runtime discards transfers to services it doesn't host on the tick
    // that would deliver them, so draining after each tick is the only
    // way to capture them. They are routed only after the commit below
    // succeeds: routing before commit leaked messages when the commit
    // failed (e.g. Raft `NotLeader` because we lost leadership between
    // dispatch and commit) — the caller retries against the new leader,
    // which routes them there, so an early send would duplicate, and if
    // the retry never comes, orphan them.
    let external = drive_capturing_external(runtime, svc_id);

    // Persist before replying. If the commit fails, we drop the reply so
    // the caller sees `Unreachable` and can retry against the new leader.
    // Doing it in this order means the client only sees success when the
    // state is durable.
    let state = runtime
        .storage
        .read(svc_id, crate::lifecycle::STATE_KEY_BYTES)
        .map(|v| v.to_vec())
        .unwrap_or_default();
    // The whole-agent delta this dispatch produced: its ordered writes
    // (STATE_KEY included), the anchor of the state it ran against
    // (recorded normatively in the log node — replay divergence
    // detection compares against it), and the effect-bearing marker
    // driving the durable-node rule. Taken even when not recording so
    // stale entries never leak into the next dispatch.
    let (writes, effect_bearing) = runtime.take_dispatch_delta(svc_id);
    let dispatch_anchor = runtime.take_dispatch_anchor(svc_id);
    let anchor = dispatch_anchor.unwrap_or((crate::effect_log::ANCHOR_UNRECORDED, [0u8; 32]));
    let commit_result = if recording_enabled {
        let mut log = runtime.finish_recording().expect("recording was started");
        log.set_anchor(anchor.0, anchor.1);
        log.set_caller_prefix(dispatch_caller_prefix);
        strategy.commit(&crate::commit::AgentDelta {
            writes: &writes,
            anchor,
            log: Some(&log),
            effect_bearing,
        })
    } else {
        strategy.commit(&crate::commit::AgentDelta {
            writes: &writes,
            anchor,
            log: None,
            effect_bearing,
        })
    };

    if let Err(e) = commit_result {
        // Drop the reply (caller surfaces `Unreachable`) and the buffered
        // transfers (nothing durable produced them), then soft-restart to
        // bring the runtime back in sync with the durable log. Don't
        // bubble the error — a transient `NotLeader` shouldn't kill the
        // agent thread.
        warn!(%svc_id, error = %e, "commit failed; soft-restarting, dropping reply and transfers");
        drop(req.reply);
        #[cfg(all(feature = "network", feature = "storage"))]
        if let Err(restart_err) = soft_restart_crdt(runtime, svc_id, strategy) {
            error!(%svc_id, "soft restart after commit failure: {restart_err}");
        }
        return Ok(());
    }

    // Commit succeeded: the state is durable, so route the buffered
    // external transfers now.
    for (target, memo) in external {
        let _ = outbox.send(Envelope {
            from: from_id,
            to: target,
            payload: memo,
        });
    }

    // Pack the reply as the full invoke wire
    // envelope `[status][state_len:u32][state][reply]` so the
    // caller's PVM sees the same shape it would for a local
    // INVOKE. `is_suspended` after `run_blocking` tells us the
    // handler yielded with a continuation still alive — STATUS_YIELDED
    // surfaces upstream so a parent agent can keep driving us tick
    // by tick. Without this distinction every cross-thread invoke
    // looks like STATUS_DONE and the caller drops yielded children
    // from its run queue.
    //
    // `take_last_reply` returns `None` only when the handler
    // panicked; we signal that to the caller by dropping
    // `reply_tx`, which surfaces upstream as `InvokeError::Panicked`.
    let reply = match runtime.take_last_reply(svc_id) {
        Some(bytes) => bytes,
        None => {
            drop(req.reply);
            return Ok(());
        }
    };
    // When the role check refused the call,
    // the runtime stashes STATUS_FORBIDDEN in last_status. That
    // wins over the default DONE/YIELDED inference so the wire
    // envelope carries the actor-level refusal end-to-end.
    let actor_status = runtime.take_last_status(svc_id);
    let status = if let Some(s) = actor_status {
        s
    } else if runtime.is_suspended(svc_id) {
        crate::actors::run::STATUS_YIELDED
    } else {
        crate::actors::run::STATUS_DONE
    };
    let envelope = encode_invoke_envelope(status, &state, &reply);
    send_reply_capped(req.reply, envelope, svc_id);
    Ok(())
}

/// Wire-byte for "no grant exists" in the registry's
/// `peer_role` / `actor_role` probe replies. Mirrors
/// `space_registry::AUTH_ROLE_NONE`; kept here so the host
/// doesn't need a cross-crate dep on the actor just to read a
/// single byte.
#[cfg(feature = "network")]
pub(crate) const AUTH_ROLE_NONE: u8 = 0;

/// Wire-byte for the space-level ADMIN grant (the highest role). Mirrors
/// `space_registry::AUTH_ROLE_ADMIN`; used by the `__stop` lifecycle gate
/// — only an admin may stop an agent host-side.
#[cfg(feature = "network")]
pub(crate) const AUTH_ROLE_ADMIN: u8 = 3;

/// Wire-byte for the lowest grant tier (read / Member). Mirrors
/// `space_registry::AUTH_ROLE_READONLY`; the floor that authorizes a
/// peer to be served a private replica's sync data.
#[cfg(all(feature = "network", feature = "storage"))]
pub(crate) const AUTH_ROLE_READONLY: u8 = 1;

/// `node_role` reply byte for an enrolled Raft VOTER: the registry's
/// `NODE_ROLE_VOTER` (0) encoded as `role + 1`. Kept as a local literal
/// — `space-registry` is only a dev-dependency of `vos`, so the const
/// can't be imported into host code; it must track
/// `space_registry::{node_role encoding, NODE_ROLE_VOTER}`.
#[cfg(feature = "network")]
pub(crate) const NODE_ROLE_REPLY_VOTER: u8 = 1;

/// The bare (un-role-gated) READ handlers on the private `msg-*` channel
/// replicas — `msg-log` (`history` / `stats`), `msg-ctl` (`commits` /
/// `commit_at` / `head`), `msg-directory` (`kp_count` / `channels`).
/// dispatch gate ([`NodeService::dispatch_invoke`]) membership-checks REMOTE
/// invokes of these: they expose ciphertext / channel metadata the sync path
/// already gates. The actors' WRITE handlers carry `#[msg(role = …)]` and are
/// intentionally ABSENT here — they're left to the actor's own gate so raft
/// leader-forward works. Must track the read surface of those three crates.
#[cfg(feature = "network")]
fn is_private_read_method(method: &str) -> bool {
    matches!(
        method,
        "history" | "stats" | "commits" | "commit_at" | "head" | "kp_count" | "channels"
    )
}

/// Build a failure envelope the libp2p layer relays back to
/// the caller when the dispatch-layer auth gate refuses a call.
/// `STATUS_FORBIDDEN` is the distinct status the client-side
/// `Invoker for &VosNode` peeks at (see `vos/src/lib.rs`) so
/// vosx surfaces "permission denied" rather than colliding with
/// a generic actor panic.
///
/// Retained post-M7 as a host-side fallback (e.g. for a future
/// quota / rate-limit gate); the actor-level role check now
/// produces STATUS_FORBIDDEN through the agent's own dispatch.
///
/// Shape: exactly 5 bytes — `[STATUS_FORBIDDEN, 0, 0, 0, 0]`
/// (status + zero-length state). Both the length and the leading
/// status byte are load-bearing for the client-side detection.
#[cfg(feature = "network")]
#[allow(dead_code)] // Retained as host-side fallback; see doc comment above.
fn forbidden_envelope() -> Vec<u8> {
    use crate::actors::run::STATUS_FORBIDDEN;
    encode_invoke_envelope(STATUS_FORBIDDEN, &[], &[])
}

/// Replay-side wrapper for already-logged messages. Always
/// emits a trusted-System prefix so the role
/// check passes during replay — original authorisation is
/// implicit in the fact the log was committed.
fn encode_replay_payload(prefix: &crate::effect_log::CallerPrefix, msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + msg.len());
    out.push(crate::actors::lifecycle::TAG_CALLER_PREFIX);
    out.extend_from_slice(prefix);
    out.extend_from_slice(msg);
    out
}

/// Wrap an inbox-sourced payload with the safe default caller
/// prefix (Caller::Unauthenticated, no role bytes). Closes the
/// forged-caller-prefix attack on Tells — see the SECURITY
/// comment in `dispatch_once`. Inbox payloads have no
/// trustworthy origin (external libp2p Tells set
/// attacker-controlled `from` fields), so the wrap *always*
/// uses Unauthenticated regardless of `env.from`.
fn wrap_with_unauthenticated_prefix(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + msg.len());
    out.push(crate::actors::lifecycle::TAG_CALLER_PREFIX);
    out.push(0); // trust_flag = external (Unauthenticated)
    out.push(0); // has_space_role
    out.push(0); // space byte (unused)
    out.push(0); // has_actor_local_role
    out.push(0); // actor_local byte (unused)
    out.extend_from_slice(msg);
    out
}

/// Enqueue `payload` for `svc_id` only if the guest can actually fetch it.
///
/// The actor's dispatch loop reads each queued item into a fixed `BUF_SIZE`
/// buffer (`lifecycle::fetch_raw`), so an item larger than that is
/// undeliverable: `fetch_raw` reports truncation (`n > buf.len()`) and the loop
/// treats it as end-of-queue, dropping the oversize item AND skipping anything
/// queued behind it in the same round. Enqueuing such an item is never useful,
/// so refuse it LOUDLY here rather than silently poisoning the queue. `payload`
/// is the already-wrapped dispatch item (caller-prefix header included), so the
/// effective message ceiling is `BUF_SIZE` minus that header.
///
/// This guard lives in the VOS dispatch layer, not `VosRuntime::send_to`, so
/// the JAR/JAM-aligned runtime and the `FETCH` hostcall stay buffer-size-
/// agnostic (a guest with a larger buffer would accept a larger item). Returns
/// `true` when the item fit and was enqueued.
fn send_if_deliverable(runtime: &mut VosRuntime, svc_id: ServiceId, payload: Vec<u8>) -> bool {
    use crate::actors::lifecycle::BUF_SIZE;
    if payload.len() > BUF_SIZE {
        tracing::warn!(
            service = svc_id.0,
            payload_len = payload.len(),
            buf_size = BUF_SIZE,
            "refusing undeliverable dispatch: wrapped payload exceeds the guest FETCH buffer \
             (BUF_SIZE); the actor cannot receive it — reduce the message size",
        );
        return false;
    }
    runtime.send_to(svc_id, payload);
    true
}

/// Drive the runtime to quiescence, buffering the external transfers each
/// tick produces before the next tick would discard them. The runtime
/// drops transfers addressed to services it doesn't host on the tick that
/// tries to deliver them, so a plain `run_blocking()` followed by one
/// `drain_external_transfers` loses any transfer bound for another agent;
/// draining after each tick captures them for the node to route.
fn drive_capturing_external(
    runtime: &mut VosRuntime,
    svc_id: ServiceId,
) -> Vec<(ServiceId, Vec<u8>)> {
    let mut external = Vec::new();
    while runtime.has_work() {
        runtime.tick_blocking();
        external.extend(runtime.drain_external_transfers(svc_id));
    }
    external
}

/// Wrap the request's message bytes with a caller-info header so the
/// PVM agent can populate `Context::caller` and the role bytes from caller info.
///
/// Layout (6 bytes header + original message):
///
///   [0] TAG_CALLER_PREFIX (0xFE)
///   [1] trust_flag: 1 iff caller is System/Actor (intra-process)
///   [2] has_space_role: 0 / 1
///   [3] space_role byte
///   [4] has_actor_local_role: 0 / 1
///   [5] actor_local_role byte
///   [6..] original message bytes
fn encode_caller_prefix(req: &InvokeRequest) -> Vec<u8> {
    let prefix = caller_prefix_bytes(req);
    let mut out = Vec::with_capacity(6 + req.msg.len());
    out.push(crate::actors::lifecycle::TAG_CALLER_PREFIX);
    out.extend_from_slice(&prefix);
    out.extend_from_slice(&req.msg);
    out
}

/// The 5 caller-prefix bytes of [`encode_caller_prefix`], standalone —
/// recorded in the dispatch's EffectLog so replay re-runs the dispatch
/// under the original caller's authority (a role-refused dispatch must
/// replay as refused).
fn caller_prefix_bytes(req: &InvokeRequest) -> crate::effect_log::CallerPrefix {
    let trust_flag: u8 = if req.caller.is_trusted() { 1 } else { 0 };
    let (has_space, space_byte) = match req.space_role {
        Some(b) => (1u8, b),
        None => (0u8, 0u8),
    };
    let (has_actor_local, actor_local_byte) = match req.actor_local_role {
        Some(b) => (1u8, b),
        None => (0u8, 0u8),
    };
    [
        trust_flag,
        has_space,
        space_byte,
        has_actor_local,
        actor_local_byte,
    ]
}

/// INVOKE. Used by the cross-thread invoke path so a yielded child on
/// another agent thread surfaces as `STATUS_YIELDED` (with its post-
/// dispatch state) to the calling actor's `lifecycle::invoke_raw`,
/// not as `STATUS_DONE`.
fn encode_invoke_envelope(status: u8, state: &[u8], reply: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + state.len() + reply.len());
    out.push(status);
    out.extend_from_slice(&(state.len() as u32).to_le_bytes());
    out.extend_from_slice(state);
    out.extend_from_slice(reply);
    out
}

/// Strip the invoke envelope back to just the rkyv-encoded reply
/// bytes for host-side callers (`VosNode::invoke`, peer invoke
/// forwarding) who don't care about YIELDED/DONE — they only want
/// the handler's return value. A short envelope or one carrying a
/// failure status (`STATUS_NOT_FOUND` / `STATUS_PANICKED` /
/// `STATUS_OOG` / `STATUS_FORBIDDEN`) decodes as `None` so the
/// gateway and other ask-style callers can distinguish "actor
/// returned nothing" from "actor failed".
fn unwrap_invoke_envelope(envelope: &[u8]) -> Option<Vec<u8>> {
    use crate::actors::run::{STATUS_DONE, STATUS_YIELDED};
    if envelope.len() < 5 {
        return None;
    }
    match envelope[0] {
        STATUS_DONE | STATUS_YIELDED => {}
        // STATUS_NOT_FOUND / STATUS_PANICKED / STATUS_OOG /
        // STATUS_FORBIDDEN and any future failure variant: the
        // actor did not produce a valid reply. Surface as None.
        _ => return None,
    }
    let state_len =
        u32::from_le_bytes([envelope[1], envelope[2], envelope[3], envelope[4]]) as usize;
    let reply_start = 5 + state_len;
    if reply_start > envelope.len() {
        return None;
    }
    Some(envelope[reply_start..].to_vec())
}

/// Decode a cross-thread invoke envelope back into the
/// [`runtime::ExternalInvokeReply`] enum the runtime's
/// `external_invoke` callback expects, so a yielded child on one
/// agent thread surfaces as [`runtime::ExternalInvokeReply::Yielded`]
/// to the calling actor's PVM.
///
/// A short envelope (just a status byte — `STATUS_NOT_FOUND` /
/// `STATUS_PANICKED`) returns `None`; the runtime then falls
/// through to its own NOT_FOUND path.
fn decode_invoke_envelope(envelope: &[u8]) -> Option<crate::runtime::ExternalInvokeReply> {
    use crate::actors::run::{STATUS_DONE, STATUS_YIELDED};
    use crate::runtime::ExternalInvokeReply;
    if envelope.len() < 5 {
        return None;
    }
    let status = envelope[0];
    let state_len =
        u32::from_le_bytes([envelope[1], envelope[2], envelope[3], envelope[4]]) as usize;
    let state_end = 5 + state_len;
    if state_end > envelope.len() {
        return None;
    }
    let state = envelope[5..state_end].to_vec();
    let reply = envelope[state_end..].to_vec();
    match status {
        STATUS_YIELDED => Some(ExternalInvokeReply::Yielded { state, reply }),
        STATUS_DONE => Some(ExternalInvokeReply::Done(reply)),
        _ => None,
    }
}

/// Run one dispatch cycle: optionally begin recording, deliver the
/// message (or just drive residual work), route external transfers,
/// then commit the resulting state via the strategy.
///
/// Returns `Err` only on host-side commit failures — those are
/// terminal for the agent. Routing failures and transient runtime
/// issues are not surfaced here.
fn dispatch_once(
    runtime: &mut VosRuntime,
    svc_id: ServiceId,
    outbox: &mpsc::Sender<Envelope>,
    from_id: ServiceId,
    msg: Option<Vec<u8>>,
    strategy: &mut dyn crate::commit::CommitStrategy,
    recording_enabled: bool,
) -> Result<(), crate::commit::CommitError> {
    let recorded = recording_enabled
        && if let Some(payload) = msg.as_ref() {
            runtime.begin_recording(payload.clone());
            true
        } else {
            false
        };
    if let Some(payload) = msg {
        // SECURITY: wrap with Caller::Unauthenticated *before*
        // dispatching so the actor's M7 dispatch_one always sees
        // a host-controlled caller prefix. Without this wrap, an
        // attacker could send a libp2p Tell whose payload begins
        // with TAG_CALLER_PREFIX (0xFE) and have dispatch_one
        // strip + parse the attacker's bytes as a "host-issued"
        // caller assertion — forging trust=System bypasses every
        // role check. With the wrap, the attacker's prefix bytes
        // become inner-message bytes the Msg decoder mis-parses
        // and rejects.
        //
        // Internal Tells (ctx.tell from one actor to another)
        // could legitimately want Caller::Actor trust, but the
        // inbox mixes them with external Tells and `env.from` is
        // attacker-controlled in the external case — so the safe
        // default is Unauthenticated for everything that arrives
        // through this path. Intra-system callers that need
        // trusted dispatch use ctx.ask (invoke path), which goes
        // through handle_invoke_request and gets the right
        // Caller::Actor wrap.
        //
        // Empty payloads are the runtime's wake-up tick (used to
        // re-schedule yielded services); the runtime filters them
        // out before dispatch and they never reach dispatch_one
        // (see `runtime.rs::run_blocking`'s round_items retain).
        // Wrapping would turn them into non-empty bytes that
        // *aren't* filtered, then trip the empty-Msg decoder.
        // Skip the wrap; empty in / empty out preserves the
        // wake-up semantics.
        let payload = if payload.is_empty() {
            payload
        } else {
            wrap_with_unauthenticated_prefix(&payload)
        };
        send_if_deliverable(runtime, svc_id, payload);
    }

    // Drive to quiescence, buffering external transfers each tick before
    // the next tick discards them; route them only after the commit
    // succeeds so a failed commit (e.g. Raft `NotLeader`) leaks nothing.
    let external = drive_capturing_external(runtime, svc_id);

    // See handle_invoke_request — the dispatch's whole-agent delta,
    // taken unconditionally so stale entries never leak across
    // dispatches.
    let (writes, effect_bearing) = runtime.take_dispatch_delta(svc_id);
    let dispatch_anchor = runtime.take_dispatch_anchor(svc_id);
    let anchor = dispatch_anchor.unwrap_or((crate::effect_log::ANCHOR_UNRECORDED, [0u8; 32]));
    if recorded {
        let mut log = runtime.finish_recording().expect("recording was started");
        log.set_anchor(anchor.0, anchor.1);
        // Tell-style dispatches were wrapped Unauthenticated; kicks
        // (empty msg) carry no prefix and replay as raw empties, so the
        // recorded prefix is unused for them.
        log.set_caller_prefix([0, 0, 0, 0, 0]);
        strategy.commit(&crate::commit::AgentDelta {
            writes: &writes,
            anchor,
            log: Some(&log),
            effect_bearing,
        })?;
    } else {
        strategy.commit(&crate::commit::AgentDelta {
            writes: &writes,
            anchor,
            log: None,
            effect_bearing,
        })?;
    }

    // Commit succeeded (the `?` above returns early on failure): the
    // state is durable, so route the buffered transfers now.
    for (target, memo) in external {
        let _ = outbox.send(Envelope {
            from: from_id,
            to: target,
            payload: memo,
        });
    }
    Ok(())
}

/// Select the agent's commit strategy from its config.
///
/// Returns `Err` when a non-`Ephemeral` strategy was requested but
/// the underlying redb open failed, or when storage was requested
/// without a `data_dir`. We deliberately do not silently downgrade
/// to `NoCommit` — a CRDT actor that can't open its DAG file
/// shouldn't pretend to be replicated.
/// Derive the per-replica `CrdtEvent.origin` from the group's
/// replication_id and the host node's 16-bit prefix.
///
/// `blake2b("vos-replica-origin/v1" || replication_id || prefix)`
/// — the prefix domain-separates replicas of the same group
/// running on different nodes, while the replication_id
/// domain-separates groups that happen to share a node. The
/// prefix string keeps this hash from colliding with other vos
/// blake2b uses (registry rep_id derivation, etc).
#[cfg(feature = "storage")]
fn derive_replica_origin(replication_id: &[u8; 32], node_prefix: u16) -> [u8; 32] {
    let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
    h.update(b"vos-replica-origin/v1");
    h.update(&[0u8]);
    h.update(replication_id);
    h.update(&node_prefix.to_le_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

fn build_agent_strategy(
    config: &AgentConfig,
    id: ServiceId,
    self_node_prefix: u16,
) -> Result<Box<dyn crate::commit::CommitStrategy>, crate::commit::CommitError> {
    #[cfg(feature = "storage")]
    {
        let _ = (id, self_node_prefix);
        match config.consistency {
            Consistency::Ephemeral => Ok(Box::new(crate::commit::NoCommit)),
            Consistency::Local => {
                let path = config.db_path(id).ok_or_else(|| {
                    crate::commit::CommitError::Config(
                        "Local consistency requires data_dir on AgentConfig".into(),
                    )
                })?;
                Ok(Box::new(crate::commit::LocalCommit::open(&path)?))
            }
            Consistency::Crdt => {
                // CRDT events are tagged with a per-replica origin
                // so peer replicas can tell our events apart from
                // theirs by content alone. Two replicas of the same
                // group share the *replication_id* (it's the group
                // identity for sync/discovery), so we can't reuse
                // that — the per-replica origin is derived from
                // `(replication_id, node_prefix)` so:
                //   - replicas on different nodes get different
                //     origins (different prefixes),
                //   - a replica's origin is stable across restarts
                //     of the same node (same prefix),
                //   - origins are domain-separated by group, so
                //     two unrelated groups on the same node never
                //     share origins.
                // We still require `replication_id` to be set
                // explicitly: an unconfigured Crdt agent has no
                // group identity to sync against, which is a
                // silent determinism failure waiting to happen.
                let replication_id = config.replication_id.ok_or_else(|| {
                    crate::commit::CommitError::Config(
                        "Crdt consistency requires AgentConfig::replication_id; \
                         set one explicitly or use `auto_replication_id(name)`"
                            .into(),
                    )
                })?;
                let replica_origin = derive_replica_origin(&replication_id, self_node_prefix);
                if let Some(arc) = &config.pre_opened_db {
                    let mut cc = match &config.pre_opened_lock {
                        Some(lock) => crate::commit::CrdtCommit::from_db_arc_locked(
                            arc.clone(),
                            lock.clone(),
                            replica_origin,
                        ),
                        None => crate::commit::CrdtCommit::from_db_arc(arc.clone(), replica_origin),
                    };
                    cc.set_node_validator(config.node_validator.clone());
                    return Ok(Box::new(cc));
                }
                let path = config.db_path(id).ok_or_else(|| {
                    crate::commit::CommitError::Config(
                        "Crdt consistency requires data_dir on AgentConfig".into(),
                    )
                })?;
                let mut cc = crate::commit::CrdtCommit::open(&path, replica_origin)?;
                cc.set_node_validator(config.node_validator.clone());
                Ok(Box::new(cc))
            }
            Consistency::Raft => {
                // Single-node-only path: agent_thread handles the
                // multi-mode case before reaching here (it owns
                // the pre-spawned worker via `config.raft_worker`).
                let cfg = crate::raft::RaftConfig {
                    me: self_node_prefix,
                    members: config.members.clone(),
                    replication_id: config.replication_id.unwrap_or([0u8; 32]),
                    ..crate::raft::RaftConfig::default()
                };
                let path = config.db_path(id).ok_or_else(|| {
                    crate::commit::CommitError::Config(
                        "Raft consistency requires data_dir on AgentConfig".into(),
                    )
                })?;
                Ok(Box::new(crate::raft::RaftCommit::open(&path, cfg)?))
            }
        }
    }
    #[cfg(not(feature = "storage"))]
    {
        let _ = (config, id, self_node_prefix);
        match config.consistency {
            Consistency::Ephemeral => Ok(Box::new(crate::commit::NoCommit)),
            other => Err(crate::commit::CommitError::Config(format!(
                "consistency={other:?} requires the `storage` feature"
            ))),
        }
    }
}

/// Max deferred messages held while waiting for a specific reply.
const MAX_DEFERRED: usize = 256;

// ── Worker thread ────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
fn extension_thread(
    id: ServiceId,
    config: ExtensionConfig,
    inbox: mpsc::Receiver<Envelope>,
    invoke_rx: mpsc::Receiver<InvokeRequest>,
    outbox: mpsc::Sender<Envelope>,
    invoke_routes: InvokeRoutes,
    agent_names: AgentNames,
    shutdown: Arc<AtomicBool>,
    activity: ActivityClock,
    proof_blobs: ProofBlobStore,
    proof_blobs_dir: Option<std::path::PathBuf>,
    raft_fwd: RaftFwd,
    #[cfg(feature = "network")] shared_network: SharedNetwork,
) -> AgentResult {
    use crate::extension::ExtensionPlugin;
    use std::collections::VecDeque;

    // SAFETY: ExtensionPlugin::load wraps libloading::Library; it's
    // only unsafe because dlopen runs the .so's static initialisers
    // and binds C symbols whose type signatures we can't verify at
    // compile time. We trust the operator's manifest path to point
    // at a vos-built extension.
    let plugin = match unsafe { ExtensionPlugin::load(&config.path) } {
        Ok(p) => p,
        Err(e) => {
            let err = format!("failed to load extension plugin: {e}");
            error!(%id, "extension: {err}");
            return AgentResult {
                id,
                panics: 1,
                error: Some(err),
            };
        }
    };

    if let Some(meta) = plugin.meta() {
        info!(
            %id,
            actor = %meta.actor_name,
            kind = ?crate::extension::ExtensionKind::from_byte(meta.kind),
            path = %config.path.display(),
            "extension: loaded plugin"
        );
        if !meta.caps.is_empty() {
            info!(%id, actor = %meta.actor_name, caps = ?meta.caps, "extension: declared capabilities");
        }
    }

    // Dispatch on plugin kind: every extension is actor-mode or
    // transport-mode, both
    // driven below. A stale `kind = Service` byte from an old blob decodes
    // back to `Actor` (see `ExtensionKind::from_byte`), so it loads on the
    // actor-mode path rather than failing.
    //
    // Transport-mode extensions (a `handle_connection(&self,
    // …)` actor) get a dedicated driver — the host owns a listener + accept
    // loop and spawns one concurrent `&self` connection task per accept on a
    // single executor thread. There are no inbound `#[msg]` handlers (the
    // macro rejects them), so `inbox`/`invoke_rx`/`outbox` go unused and drop
    // when this frame returns; callers of a transport extension get no reply.
    // `invoke_routes` IS passed: a conn task's `ctx.ask` routes
    // an outbound `InvokeRequest` through it with a per-call async reply channel.
    if plugin.kind() == crate::extension::ExtensionKind::Transport {
        return run_transport_extension(
            id,
            plugin,
            config,
            shutdown,
            activity,
            invoke_routes,
            raft_fwd,
        );
    }

    let bump = || *activity.lock().unwrap() = Instant::now();

    // Pick a persistence strategy. Extensions always get LocalCommit
    // when a data directory is configured, NoCommit otherwise;
    // replication strategies (CRDT, Raft) are not available to
    // extensions since they live outside the deterministic universe.
    let mut strategy: Box<dyn crate::commit::CommitStrategy> =
        build_extension_strategy(&config, id);
    let saved_state = strategy.restore();

    let mut instance = match saved_state {
        Some(bytes) => {
            info!(%id, bytes = bytes.len(), "extension: restored state");
            plugin.load_state(&bytes)
        }
        None if config.init_args.is_empty() => plugin.create(),
        None => plugin.create_with_args(&config.init_args),
    };

    // Messages that arrived while we were waiting for a specific reply.
    // Bounded to prevent OOM from a misbehaving sender (see MAX_DEFERRED).
    let mut deferred: VecDeque<Envelope> = VecDeque::new();

    let blob_fetch = BlobFetchCtx {
        proof_blobs: &proof_blobs,
        proof_blobs_dir: proof_blobs_dir.as_deref(),
        #[cfg(feature = "network")]
        shared_network: &shared_network,
    };

    // Host-side cooperative executor. Created once on THIS thread
    // (the thread that owns the instance) and driven per-message via
    // `block_on(ex.run(..))`. The `!Send` per-task futures stay local to it.
    // Actor-mode is N=1 (one root task to completion before the next message),
    // so no task is ever spawned on it here; `&self` transport services add
    // `ex.spawn`. async-io's single process-global reactor (shared across all
    // extension threads) doubles as the byte-stream reactor.
    let ex = async_executor::LocalExecutor::new();
    // Per-instance byte-stream reactor state (open TCP listeners +
    // connections). Lives across dispatches so a listener bound in one invoke
    // stays open for later accepts; dropped (closing all fds) at thread end.
    // Build the TLS acceptor once from the configured cert/key so
    // `listen_tls` listeners can terminate TLS host-side.
    let tls_acceptor = match (
        config.tls_cert_pem.as_deref(),
        config.tls_key_pem.as_deref(),
    ) {
        (Some(cert), Some(key)) => build_tls_acceptor(cert, key, id),
        _ => None,
    };
    let mut reactor = ReactorTables::new(tls_acceptor);

    // Periodic `tick()`. When the manifest set `tick_ms`, the
    // driver dispatches a synthetic `tick` message to the actor's `tick`
    // handler about every interval, *between* inbound work. Best-effort cadence: a
    // long invoke delays the next tick (the driver never preempts a handler).
    // `tick_disabled` latches if the extension declares `tick_ms` but has no
    // `tick` handler (the synthetic dispatch returns `Err`), so a misconfig
    // logs once instead of re-dispatching every interval.
    let tick_interval = config.tick_ms.map(Duration::from_millis);
    let mut tick_deadline = tick_interval.map(|iv| Instant::now() + iv);
    let mut tick_disabled = false;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Fire a due periodic tick before servicing inbound work, so a
        // backlog of invokes can't starve the heartbeat indefinitely.
        if let (Some(deadline), false) = (tick_deadline, tick_disabled) {
            if Instant::now() >= deadline {
                bump();
                let payload = encode_tick_payload();
                // No external caller → RELAY_CALLER unset → a tick's
                // `ctx.ask_dispatch` relays as `Unauthenticated`
                // (no authenticated caller to propagate).
                let outcome = dispatch_and_poll(
                    &ex,
                    &mut instance,
                    &payload,
                    &inbox,
                    &outbox,
                    id,
                    &mut deferred,
                    &blob_fetch,
                    &mut reactor,
                    &invoke_routes,
                    &config.intra_caps,
                    &agent_names,
                    &raft_fwd,
                );
                if matches!(outcome, DispatchOutcome::Err) {
                    warn!(
                        %id,
                        "extension: tick_ms set but `tick` dispatch failed (no `tick` handler?) \
                         — disabling periodic ticks"
                    );
                    tick_disabled = true;
                }
                persist(strategy.as_mut(), &instance, id);
                // Re-arm from *now* (not deadline+iv) so a slow tick doesn't
                // build up a burst of catch-up ticks.
                tick_deadline = tick_interval.map(|iv| Instant::now() + iv);
            }
        }

        // Process up to a few invoke requests per iteration to avoid
        // starving the regular inbox.
        for _ in 0..4 {
            match invoke_rx.try_recv() {
                Ok(req) => {
                    bump();
                    // Stamp the real caller of this invoke for
                    // the duration of the dispatch, so an `EFFECT_ASK_DISPATCH`
                    // raised by the handler relays it (bounded by `intra_caps`)
                    // instead of the `Caller::Actor` bypass. RAII-cleared after
                    // the dispatch (and on panic, via the catch in run_ext_task)
                    // so it never leaks to the next invoke or a self-originated
                    // call. The envelope path below leaves it unstamped → such
                    // calls relay as `Unauthenticated`.
                    let outcome = {
                        let _relay = RelayCallerGuard::stamp(PropagatedCaller {
                            caller: req.caller.clone(),
                            space_role: req.space_role,
                        });
                        dispatch_and_poll(
                            &ex,
                            &mut instance,
                            &req.msg,
                            &inbox,
                            &outbox,
                            id,
                            &mut deferred,
                            &blob_fetch,
                            &mut reactor,
                            &invoke_routes,
                            &config.intra_caps,
                            &agent_names,
                            &raft_fwd,
                        )
                    };
                    // Workers don't yield — pack as DONE with no
                    // state so the caller's invoke_raw decodes
                    // `InvokeResult::Done { state: empty, reply }`.
                    // A `DispatchOutcome::Err` (handler panicked,
                    // missing future, etc) becomes STATUS_PANICKED
                    // so the gateway's `unwrap_invoke_envelope`
                    // can distinguish it from a legitimate `()`
                    // return — see vos::actors::run::STATUS_*.
                    let envelope = match outcome {
                        DispatchOutcome::Ok(reply) => {
                            encode_invoke_envelope(crate::actors::run::STATUS_DONE, &[], &reply)
                        }
                        DispatchOutcome::Err => {
                            encode_invoke_envelope(crate::actors::run::STATUS_PANICKED, &[], &[])
                        }
                    };
                    send_reply_capped(req.reply, envelope, id);
                    persist(strategy.as_mut(), &instance, id);
                }
                Err(_) => break,
            }
        }

        // Take next message: deferred first, then inbox. Cap the inbox wait
        // at the time remaining until the next tick (when ticking) so the
        // heartbeat cadence holds even with an otherwise-idle inbox; floor at
        // the regular 50ms poll otherwise.
        let recv_timeout = match tick_deadline {
            Some(deadline) if !tick_disabled => deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(50)),
            _ => Duration::from_millis(50),
        };
        let envelope = if let Some(e) = deferred.pop_front() {
            bump();
            e
        } else {
            match inbox.recv_timeout(recv_timeout) {
                Ok(e) => {
                    bump();
                    e
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        };

        // Envelope path: actor-to-actor messaging carries no external caller,
        // so `RELAY_CALLER` stays unset → any `ctx.ask_dispatch` here relays as
        // `Unauthenticated` (no authenticated caller to propagate).
        let outcome = dispatch_and_poll(
            &ex,
            &mut instance,
            &envelope.payload,
            &inbox,
            &outbox,
            id,
            &mut deferred,
            &blob_fetch,
            &mut reactor,
            &invoke_routes,
            &config.intra_caps,
            &agent_names,
            &raft_fwd,
        );
        // Envelope-mode replies don't carry the `[status][state][reply]`
        // wrapper — that's an invoke-channel detail. On the envelope
        // path the receiver just gets the reply bytes addressed
        // `from = target`. Treat a `DispatchOutcome::Err` as an empty
        // reply here (we lose the panic vs () distinction in the
        // envelope path, but no caller demands it today — the
        // ask-style path that *does* distinguish them goes through
        // invoke). Always reply even on empty so an ask-style caller
        // doesn't hang for the full reply timeout.
        let reply_bytes = match outcome {
            DispatchOutcome::Ok(b) => b,
            DispatchOutcome::Err => Vec::new(),
        };
        let _ = outbox.send(Envelope {
            from: id,
            to: envelope.from,
            payload: reply_bytes,
        });
        persist(strategy.as_mut(), &instance, id);
    }

    AgentResult {
        id,
        panics: 0,
        error: None,
    }
}

// ── Service-mode extension runner ──────────────────────────

/// Caller context an extension relays on an outbound call: the
/// identity that invoked the extension's handler plus its space-wide
/// role byte. Propagated so the extension acts as a transparent
/// relay — the downstream actor sees who really called, not the
/// extension's own id.
///
/// `actor_local_role` is intentionally dropped: the incoming byte was
/// computed for the *extension* as target and is meaningless for a
/// downstream actor; v1 doesn't re-look-up per-target actor-local
/// grants on the extension path — the same limitation the libp2p
/// dispatch path has (it only probes actor-local for the registry).
#[derive(Clone, Debug)]
struct PropagatedCaller {
    caller: crate::actors::Caller,
    space_role: Option<u8>,
}

thread_local! {
    /// The caller of the invoke the actor-mode driver is *currently*
    /// handling on this agent's thread. `extension_thread` stamps it (via
    /// [`RelayCallerGuard`]) before driving an invoke-path `dispatch_and_poll`
    /// and clears it after; the `EFFECT_ASK_DISPATCH` fulfiller reads its own
    /// thread's slot to relay the real caller (bounded by `intra_caps`). `Some`
    /// for an inbound invoke, `None` for self-originated work — the envelope
    /// path and a periodic `tick` leave it unstamped — which relays as
    /// `Unauthenticated`. Keyed implicitly by thread, so concurrent agents
    /// never clobber each other's caller.
    static RELAY_CALLER: core::cell::RefCell<Option<PropagatedCaller>> =
        const { core::cell::RefCell::new(None) };
}

/// RAII guard: stamp the current relay caller for the duration of one
/// actor-mode invoke dispatch, clearing it on drop. Drop runs even if the
/// dispatched handler panics (it unwinds past this guard's scope), so a
/// refused/exploding call never leaves a stale caller to poison the next
/// dispatch on this thread.
struct RelayCallerGuard;

impl RelayCallerGuard {
    fn stamp(pc: PropagatedCaller) -> Self {
        RELAY_CALLER.with(|c| *c.borrow_mut() = Some(pc));
        RelayCallerGuard
    }
}

impl Drop for RelayCallerGuard {
    fn drop(&mut self) {
        RELAY_CALLER.with(|c| *c.borrow_mut() = None);
    }
}

/// Read this thread's current relay caller, if an actor-mode invoke
/// dispatch is in flight on it.
fn current_relay_caller() -> Option<PropagatedCaller> {
    RELAY_CALLER.with(|c| c.borrow().clone())
}

/// Well-known instance name of the space registry. Used by
/// [`VosNode::record_agent_name`] to seed the [`AgentNames`] reverse
/// map for the registry's fixed [`ServiceId::REGISTRY`] even when it's
/// registered from a bare `AgentConfig`, so the registry resolves
/// name-from-id through the same map as every other installed agent
/// rather than via a special case.
pub const REGISTRY_AGENT_NAME: &str = "space-registry";

/// Well-known instance name of the hyperspace (federation) registry
/// replica. The sync-serve gate hardcodes it to `Public` — the hyperspace
/// registry is the deliberately-ungated federation surface. Set on the
/// replica's `AgentConfig` at [`VosNode::attach_network`] so `slot.name`
/// carries it (a bare `AgentConfig` would leave the name empty).
pub const HYPERSPACE_REGISTRY_AGENT_NAME: &str = "hyperspace-registry";

/// R4 — the propagated peer's actor-local grant on the relay's final
/// target, to be carried on the relayed call so an explicit per-actor
/// grant reaches the target through an extension exactly as it would on
/// a direct libp2p call (which [`NodeService::dispatch_invoke`] now
/// probes too). Returns `(peer_bytes, role)` when all hold:
///
/// - the extension's caps permit the relay at all (`cap_for` is `Some`
///   for the target) — the cap gates *whether* the extension may reach
///   the target, even though it can't bound the grant's magnitude;
/// - the target resolved to a name (so the registry can be keyed);
/// - the propagated caller is a `Peer` (only Peers have actor-local
///   grants; trusted/anonymous callers carry none);
/// - the registry has a non-`AUTH_ROLE_NONE` row for `(peer, target)`.
///
/// The role is in the **target actor's own role space** and is relayed
/// *uncapped*: the host can't compare it to the SpaceRole ceiling, and
/// it's faithful — the peer already holds exactly this on a direct
/// call, so the relay is a conduit, not an amplifier. It overrides
/// `space_role` at the target, so the caller must carry the matching
/// `Peer` identity (the invoke_fn re-stamps it).
#[cfg(feature = "network")]
fn relay_actor_local_role(
    routes: &InvokeRoutes,
    propagated: Option<&PropagatedCaller>,
    caps: &[crate::actors::IntraCap],
    target_name: Option<&str>,
) -> Option<(Vec<u8>, u8)> {
    use crate::actors::{Caller, cap_for};
    // The cap must permit the relay to this target at all.
    cap_for(caps, target_name)?;
    let name = target_name?;
    let Caller::Peer(bytes) = &propagated?.caller else {
        return None;
    };
    use crate::actors::codec::Encode;
    use crate::value::{Msg, TAG_DYNAMIC};
    let msg = Msg::new("actor_role")
        .with("peer_id", bytes.clone())
        .with("agent_name", name);
    let mut payload = Vec::with_capacity(1 + 64);
    payload.push(TAG_DYNAMIC);
    payload.extend_from_slice(&msg.encode());
    let role = registry_probe_u8(routes, payload)?;
    // AUTH_ROLE_NONE (0) is "no row"; mirror the dispatch path and treat
    // it as no grant (an actor whose lowest tier is 0 can't be granted
    // actor-locally — a known, pre-existing limitation).
    (role != AUTH_ROLE_NONE).then_some((bytes.clone(), role))
}

/// Compute the `(caller, space_role byte)` an extension relays for an
/// outbound `ctx.ask_dispatch` to `target_name`, applying the
/// intersection model: the effective authority is
/// `min(caller's space role, the extension's declared cap ceiling for
/// the target)`. The extension can never *amplify* the caller, and
/// the caller can never reach actors the extension didn't declare.
/// (Actor-local grants are handled separately by
/// [`relay_actor_local_role`] — they're per-actor, in the target's own
/// role space, and pass through faithfully rather than via this cap.)
///
/// The returned caller is always NON-trusted (Peer or
/// Unauthenticated) so the downstream actor's role check actually
/// consults the (capped) `space_role` rather than short-circuiting
/// through the [`Caller::is_trusted`] bypass.
///
/// - No matching cap → `(Unauthenticated, None)`: the extension has
///   no authority for this target; role-gated handlers refuse.
/// - `propagated == None` (a `run()`-thread / self-originated call
///   with no external caller) → `(Unauthenticated, None)`.
/// - Peer caller → relays the peer's identity + `min(space_role,
///   ceiling)`.
/// - System / Actor caller (trusted incoming) → relays anonymously
///   (`Unauthenticated`) carrying `min(Admin, ceiling)`: trusted
///   callers have full authority, but the cap still bounds it, and
///   dropping the trusted variant keeps the cap effective.
fn resolve_relay_caller(
    propagated: Option<&PropagatedCaller>,
    caps: &[crate::actors::IntraCap],
    target_name: Option<&str>,
) -> (crate::actors::Caller, Option<u8>) {
    use crate::actors::{Caller, SpaceRole, cap_for};

    let Some(ceiling) = cap_for(caps, target_name) else {
        return (Caller::Unauthenticated, None);
    };
    let Some(pc) = propagated else {
        return (Caller::Unauthenticated, None);
    };
    // The caller's effective space-wide authority entering the relay.
    let carried: Option<SpaceRole> = match &pc.caller {
        Caller::Peer(_) => pc.space_role.and_then(SpaceRole::from_u8),
        // Trusted incoming (host-initiated or intra-system) carries
        // full authority — but is still bounded by the cap below.
        Caller::System | Caller::Actor(_) => Some(SpaceRole::Admin),
        Caller::Unauthenticated => None,
    };
    let Some(carried) = carried else {
        return (Caller::Unauthenticated, None);
    };
    let effective = carried.min(ceiling);
    // The carrier must be non-trusted so the downstream role check
    // uses the capped space_role instead of short-circuiting.
    // Preserve the peer's identity (audit / future per-target
    // actor-local lookups); relay trusted callers anonymously.
    let carrier = match &pc.caller {
        Caller::Peer(bytes) => Caller::Peer(bytes.clone()),
        _ => Caller::Unauthenticated,
    };
    (carrier, Some(effective.as_u8()))
}

/// Outcome of a single extension dispatch. `Ok(bytes)` means the
/// handler completed with the given reply (`bytes` may be empty
/// for a `()` return). `Err` covers the cases that can't be
/// represented as bytes — handler panic, decode failure, missing
/// future — and lets `extension_thread` pick the right `STATUS_*`
/// byte for the invoke envelope. The exact `POLL_ERR_*` code
/// behind the failure is logged inside `dispatch_and_poll` (the
/// caller doesn't need it to pick a status byte).
enum DispatchOutcome {
    Ok(Vec<u8>),
    Err,
}

/// Host-side context the extension thread hands to `handle_effect`
/// — bundles the proof-blob CAS with optional cross-node fan-out
/// and on-disk persistence.
struct BlobFetchCtx<'a> {
    proof_blobs: &'a ProofBlobStore,
    proof_blobs_dir: Option<&'a std::path::Path>,
    #[cfg(feature = "network")]
    shared_network: &'a SharedNetwork,
}

/// One accepted byte-stream connection: either a plaintext TCP stream or a
/// host-terminated TLS stream over one. Both impl `futures_io::AsyncRead/Write`,
/// So the extension reads/writes plaintext bytes either way.
enum Conn {
    Plain(async_io::Async<std::net::TcpStream>),
    // Boxed — a rustls `TlsStream` is large; keep the enum small.
    Tls(Box<futures_rustls::server::TlsStream<async_io::Async<std::net::TcpStream>>>),
}

impl Conn {
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use futures_lite::AsyncReadExt;
        match self {
            Conn::Plain(s) => s.read(buf).await,
            Conn::Tls(s) => s.read(buf).await,
        }
    }

    async fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        use futures_lite::AsyncWriteExt;
        let n = match self {
            Conn::Plain(s) => s.write(data).await,
            Conn::Tls(s) => s.write(data).await,
        }?;
        // Flush so TLS records (which rustls buffers) actually reach the peer
        // before the handler moves on / closes. A no-op on a plain TCP stream.
        match self {
            Conn::Plain(s) => s.flush().await,
            Conn::Tls(s) => s.flush().await,
        }?;
        Ok(n)
    }
}

/// One open listener + whether the host terminates TLS on its connections.
struct ListenerEntry {
    listener: async_io::Async<std::net::TcpListener>,
    tls: bool,
}

/// Per-instance host reactor state for the byte-stream effects.
/// Holds the extension's open TCP listeners + connections as `async_io::Async`
/// handles (registered with async-io's single process-global reactor); lives
/// for the extension thread's lifetime so a listener bound in one dispatch can
/// be accepted-on in a later one. Dropping it closes every fd.
///
/// `tls_acceptor` is built once (in `extension_thread`) from the extension's
/// configured cert/key; `listen_tls` listeners wrap each accepted connection
/// with it so the extension only ever sees plaintext.
struct ReactorTables {
    listeners: std::collections::HashMap<u64, ListenerEntry>,
    conns: std::collections::HashMap<u64, Conn>,
    next_id: u64,
    tls_acceptor: Option<futures_rustls::TlsAcceptor>,
}

impl ReactorTables {
    fn new(tls_acceptor: Option<futures_rustls::TlsAcceptor>) -> Self {
        Self {
            listeners: std::collections::HashMap::new(),
            conns: std::collections::HashMap::new(),
            next_id: 1,
            tls_acceptor,
        }
    }
    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

/// Build a TLS acceptor from PEM cert chain + private key. Returns `None` (with
/// a logged warning) on any parse/config error so a misconfigured cert degrades
/// to "no TLS" rather than killing the extension thread.
fn build_tls_acceptor(
    cert_pem: &[u8],
    key_pem: &[u8],
    id: ServiceId,
) -> Option<futures_rustls::TlsAcceptor> {
    use futures_rustls::rustls::{self, pki_types::CertificateDer};
    // Install the ring provider once (idempotent — matches http-gateway/http3).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut cert_rd = cert_pem;
    let certs: Vec<CertificateDer<'static>> = match rustls_pemfile::certs(&mut cert_rd).collect() {
        Ok(c) => c,
        Err(e) => {
            error!(%id, "extension: TLS cert PEM parse failed: {e}");
            return None;
        }
    };
    if certs.is_empty() {
        error!(%id, "extension: TLS cert PEM contained no certificates");
        return None;
    }
    let mut key_rd = key_pem;
    let key = match rustls_pemfile::private_key(&mut key_rd) {
        Ok(Some(k)) => k,
        Ok(None) => {
            error!(%id, "extension: TLS key PEM contained no private key");
            return None;
        }
        Err(e) => {
            error!(%id, "extension: TLS key PEM parse failed: {e}");
            return None;
        }
    };
    match rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
    {
        Ok(config) => Some(futures_rustls::TlsAcceptor::from(std::sync::Arc::new(
            config,
        ))),
        Err(e) => {
            error!(%id, "extension: rustls server config failed: {e}");
            None
        }
    }
}

/// Largest single `read` the host will buffer, capping a handler-supplied
/// `max` so a bad value can't request a huge allocation.
const MAX_READ: u32 = 1 << 20;

/// Idle deadline on a transport connection's `read`. A peer
/// that opens a connection and then sends nothing (or dribbles bytes more
/// slowly than this) gets its read error out, so the handler drops the
/// connection and frees its host slot — bounding slow-loris / idle
/// keep-alive exhaustion (the
/// transport substrate has no extension-facing timer effect, so the deadline
/// lives host-side). Resets on every read, so a steadily-progressing transfer
/// is never cut off.
const READ_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Upper bound a transport conn task waits for an invoke reply
/// on BOTH `EFFECT_ASK` (`ctx.ask`) and `EFFECT_ASK_DISPATCH` (`ctx.ask_dispatch`)
/// before giving up (empty / RESP_ERR). Matches the 300 s the cross-node
/// `dispatch_invoke` uses, so
/// a legitimately long-running upstream handler (e.g. a STARK prove, ~3 min)
/// still returns 200 rather than a premature 502. The await yields
/// cooperatively, so a parked ask never pins the executor thread; the only
/// cost of a slow/missing target is one of the host's bounded connection slots.
const ASK_TIMEOUT: Duration = Duration::from_secs(300);

/// Leader-forwarding context for the extension ask path. Bundles the
/// shared network handle with the host's [`RaftHosts`] map so
/// [`route_invoke`] can recognize a follower-rejected write (the local
/// replica drops the reply when its commit fails NotLeader) and
/// re-address the invoke to the group's current leader over the wire.
/// `Default` is the inert form (no network, no raft hosts) used by
/// builds without the network/storage features and by tests.
#[derive(Clone, Default)]
struct RaftFwd {
    #[cfg(all(feature = "network", feature = "storage"))]
    network: SharedNetwork,
    #[cfg(all(feature = "network", feature = "storage"))]
    hosts: RaftHosts,
}

/// Outcome of awaiting the local invoke reply in [`route_invoke`].
/// `Canceled` (the target dropped its reply sender) is kept distinct
/// from `Timeout` and from a real envelope because it is the signature
/// of a Raft follower refusing a write — the one case worth retrying
/// against the group's leader. A handler panic also lands here; the
/// leader-role check in [`forward_to_raft_leader`] filters that out.
enum AskOutcome {
    Reply(Vec<u8>),
    Canceled,
    Timeout,
}

/// The async effect router handed to [`run_ext_task`]. Bundles the host-side
/// channels + blob store + byte-stream reactor a `TASK_PENDING` is fulfilled
/// against.
///
/// Request-reply effects (EFFECT_ASK / FETCH / BLOB_GET / BLOB_PUT) stay on the
/// synchronous [`handle_effect`] transport (EFFECT_ASK rides the envelope path —
/// `outbox.send` + `wait_for_reply` — preserving the deferred-queue semantics
/// `extension_to_extension_ask` depends on). Calling it inline is
/// behaviour-identical because actor-mode is **N=1**.
/// The **byte-stream** effects genuinely `await` `smol::Async` TCP ops on
/// the executor thread, driven by `block_on(ex.run(..))` polling async-io's
/// reactor — this is where the host executor + reactor earn their keep.
struct Fulfiller<'a> {
    inbox: &'a mpsc::Receiver<Envelope>,
    outbox: &'a mpsc::Sender<Envelope>,
    extension_id: ServiceId,
    deferred: &'a mut std::collections::VecDeque<Envelope>,
    blob_fetch: &'a BlobFetchCtx<'a>,
    reactor: &'a mut ReactorTables,
    /// Outbound-invoke routing table — an actor-mode
    /// extension's `ctx.ask_dispatch` routes through the host invoke substrate
    /// (per-call async reply, status-framed, reaches PVM targets) rather than
    /// the message-envelope `wait_for_reply` path that `ctx.ask` uses.
    invoke_routes: &'a InvokeRoutes,
    /// The extension's declared intra-system caps. An
    /// `EFFECT_ASK_DISPATCH` relays the real caller of the invoke in flight
    /// (read from `RELAY_CALLER`), bounded by `min(caller role, cap ceiling)`
    /// for the target — never the `Caller::Actor` intra-system bypass — so a
    /// role-gated target (e.g. the registry's admin-gated `publish`) still
    /// consults the caller's real role.
    intra_caps: &'a [crate::actors::IntraCap],
    /// Host reverse map `local_id → instance_name` — resolves
    /// the ask target's name so `intra_caps` (declared by name) bind, and so
    /// the propagated peer's actor-local grant can be looked up.
    agent_names: &'a AgentNames,
    /// Leader-forwarding context for asks that target a raft-hosted
    /// agent whose local replica is a follower.
    raft_fwd: &'a RaftFwd,
}

impl Fulfiller<'_> {
    async fn fulfill(&mut self, effect: &[u8]) -> Vec<u8> {
        use crate::effects::{
            EFFECT_ACCEPT, EFFECT_ASK_DISPATCH, EFFECT_CLOSE, EFFECT_LISTEN, EFFECT_READ,
            EFFECT_WRITE,
        };
        match effect.first().copied() {
            Some(EFFECT_LISTEN | EFFECT_ACCEPT | EFFECT_READ | EFFECT_WRITE | EFFECT_CLOSE) => {
                self.fulfill_bytestream(effect[0], &effect[1..]).await
            }
            // Status-framed invoke-path ask: routes through
            // `invoke_routes`, returning `[RESP_OK][reply]` / `[RESP_ERR]` —
            // the `Option<Vec<u8>>` contract `ctx.ask_dispatch` decodes (the
            // old `ServiceCtx::ask_raw` shape).
            //
            // SECURITY: the relayed caller is NOT `Caller::Actor` (that's the
            // intra-system role-bypass — it would let any caller's `dev
            // publish` reach the registry's admin-gated handler as trusted).
            // Instead relay the real caller of the invoke currently in flight
            // on this thread (`RELAY_CALLER`, stamped by `extension_thread`
            // before driving this dispatch), bounded by `min(caller role,
            // intra_cap ceiling for the target)`. A target the extension declared
            // no cap for collapses to `Unauthenticated`; a self-originated
            // call (no stamp) likewise relays anonymously. Deny-by-default.
            Some(EFFECT_ASK_DISPATCH) => {
                use crate::effects::bytestream as bs;
                let rest = &effect[1..];
                if rest.len() < 4 {
                    return bs::resp_err("");
                }
                let target = u32::from_le_bytes(rest[..4].try_into().unwrap());
                let target_name = self
                    .agent_names
                    .read()
                    .ok()
                    .and_then(|m| m.get(&local_id_of(target)).cloned());
                let propagated = current_relay_caller();
                #[allow(unused_mut)]
                let (mut caller, space_role) = resolve_relay_caller(
                    propagated.as_ref(),
                    self.intra_caps,
                    target_name.as_deref(),
                );
                // Faithfully propagate the propagated peer's actor-local grant
                // on the final target (in the target's own role space, relayed
                // uncapped — the cap only gates *whether* the relay may reach
                // the target). Overrides `space_role`, so the carrier must stay
                // the Peer for the override to bind. Only Peer callers (libp2p
                // gate) carry one, so this is `network`-only.
                #[cfg(feature = "network")]
                let actor_local_role = match relay_actor_local_role(
                    self.invoke_routes,
                    propagated.as_ref(),
                    self.intra_caps,
                    target_name.as_deref(),
                ) {
                    Some((peer_bytes, role)) => {
                        caller = crate::actors::Caller::Peer(peer_bytes);
                        Some(role)
                    }
                    None => None,
                };
                #[cfg(not(feature = "network"))]
                let actor_local_role: Option<u8> = None;
                match route_invoke(
                    self.invoke_routes,
                    self.raft_fwd,
                    self.extension_id,
                    caller,
                    space_role,
                    actor_local_role,
                    rest,
                )
                .await
                {
                    Some(reply) => bs::resp_ok_bytes(&reply),
                    None => bs::resp_err(""),
                }
            }
            // Other request-reply effects (EFFECT_ASK / FETCH / BLOB_GET /
            // BLOB_PUT) keep the synchronous envelope transport.
            _ => handle_effect(
                effect,
                self.inbox,
                self.outbox,
                self.extension_id,
                self.deferred,
                self.blob_fetch,
            ),
        }
    }

    /// Run one byte-stream op against the reactor tables. Each arm `await`s the
    /// matching `async_io::Async` operation; the result is encoded back to the
    /// handler via the `bytestream` response codec (status-led; errors carry a
    /// message the handler sees as `None`).
    async fn fulfill_bytestream(&mut self, tag: u8, rest: &[u8]) -> Vec<u8> {
        use crate::effects::bytestream as bs;
        use crate::effects::{
            EFFECT_ACCEPT, EFFECT_CLOSE, EFFECT_LISTEN, EFFECT_READ, EFFECT_WRITE,
        };

        match tag {
            EFFECT_LISTEN => {
                let Some((tls, addr)) = bs::decode_listen(rest) else {
                    return bs::resp_err("listen: bad request");
                };
                if tls && self.reactor.tls_acceptor.is_none() {
                    return bs::resp_err("listen_tls: no TLS cert configured for this extension");
                }
                match std::net::TcpListener::bind(&addr)
                    .and_then(async_io::Async::<std::net::TcpListener>::new)
                {
                    Ok(listener) => {
                        let id = self.reactor.alloc_id();
                        self.reactor
                            .listeners
                            .insert(id, ListenerEntry { listener, tls });
                        bs::resp_ok_u64(id)
                    }
                    Err(e) => bs::resp_err(&format!("listen {addr}: {e}")),
                }
            }
            EFFECT_ACCEPT => {
                let Some(lid) = bs::decode_accept(rest) else {
                    return bs::resp_err("accept: bad request");
                };
                let (accepted, tls) = match self.reactor.listeners.get(&lid) {
                    Some(entry) => (entry.listener.accept().await, entry.tls),
                    None => return bs::resp_err("accept: unknown listener"),
                };
                let stream = match accepted {
                    Ok((stream, _addr)) => stream,
                    Err(e) => return bs::resp_err(&format!("accept: {e}")),
                };
                // Terminate TLS host-side for `listen_tls` listeners; the
                // extension then reads/writes plaintext through `Conn`.
                let conn = if tls {
                    // Acceptor presence was checked at listen time.
                    let acceptor = self.reactor.tls_acceptor.clone().unwrap();
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => Conn::Tls(Box::new(tls_stream)),
                        Err(e) => return bs::resp_err(&format!("tls handshake: {e}")),
                    }
                } else {
                    Conn::Plain(stream)
                };
                let id = self.reactor.alloc_id();
                self.reactor.conns.insert(id, conn);
                bs::resp_ok_u64(id)
            }
            EFFECT_READ => {
                let Some((cid, max)) = bs::decode_read(rest) else {
                    return bs::resp_err("read: bad request");
                };
                let Some(conn) = self.reactor.conns.get_mut(&cid) else {
                    return bs::resp_err("read: unknown conn");
                };
                let mut buf = alloc::vec![0u8; max.min(MAX_READ) as usize];
                // Race the read against an idle deadline, same as the transport
                // `ConnFulfiller`: a silent / dribbling peer must not park this
                // agent thread forever (slow-loris) — `block_on(ex.run(..))` is
                // this actor's only thread, so a stuck read blocks the whole
                // agent (incl. its ability to be stopped).
                let outcome: Option<std::io::Result<usize>> =
                    futures_lite::future::or(async { Some(conn.read(&mut buf).await) }, async {
                        async_io::Timer::after(READ_IDLE_TIMEOUT).await;
                        None
                    })
                    .await;
                match outcome {
                    // n == 0 → EOF → ok-empty (the handler reads `Some(empty)`).
                    Some(Ok(n)) => {
                        buf.truncate(n);
                        bs::resp_ok_bytes(&buf)
                    }
                    Some(Err(e)) => bs::resp_err(&format!("read: {e}")),
                    None => {
                        warn!(extension_id = %self.extension_id, cid, "actor-mode read idle timeout");
                        bs::resp_err("read: idle timeout")
                    }
                }
            }
            EFFECT_WRITE => {
                let Some((cid, data)) = bs::decode_write(rest) else {
                    return bs::resp_err("write: bad request");
                };
                let Some(conn) = self.reactor.conns.get_mut(&cid) else {
                    return bs::resp_err("write: unknown conn");
                };
                match conn.write(&data).await {
                    Ok(n) => bs::resp_ok_u32(n as u32),
                    Err(e) => bs::resp_err(&format!("write: {e}")),
                }
            }
            EFFECT_CLOSE => {
                if let Some(cid) = bs::decode_close(rest) {
                    // Drop closes the fd; idempotent on an unknown id.
                    self.reactor.conns.remove(&cid);
                }
                bs::resp_ok_empty()
            }
            _ => bs::resp_err("bytestream: unknown tag"),
        }
    }
}

/// Per-connection effect fulfiller for a transport-mode connection task
///. Where the actor-mode [`Fulfiller`] services byte ops
/// against a shared [`ReactorTables`], a `ConnFulfiller` **owns its single
/// [`Conn`]** — moved in from the host accept loop, never inserted into any
/// shared table — so the N concurrent connection tasks never contend on a
/// reactor map across an `await` (the shared `conns` map can't be borrowed by
/// two parked tasks at once). Its `ReactorTables.conns` stays empty for a
/// transport instance by construction.
///
/// It services [`EFFECT_READ`]/[`EFFECT_WRITE`]/[`EFFECT_CLOSE`] against the
/// owned conn, validating the handler-supplied `conn_id` matches its own (a
/// Foreign id → the handler decodes `None`), and
/// [`EFFECT_ASK`] by routing an outbound `InvokeRequest` through
/// `invoke_routes` with a per-call **async** reply channel
/// ([`ReplyChannel::Async`]) — correlated per-call (no shared-inbox sender-id
/// ambiguity) and awaited on the executor (no blocking-pool thread), so other
/// connection tasks keep serving. The relayed caller is
/// [`Caller::Unauthenticated`] (a conn task has no inbound authenticated
/// caller). The remaining effects are still rejected in v1:
///   - `EFFECT_LISTEN`/`ACCEPT` — the host owns the accept loop; a connection
///     task cannot bind or accept.
///   - `EFFECT_FETCH`/`BLOB_GET`/`BLOB_PUT` — synchronous/blocking on the
///     executor thread; not supported from a connection task.
struct ConnFulfiller {
    /// The owned connection. `None` after an explicit `close` of the matching
    /// `cid`; a byte op against a closed conn returns an error (handler sees
    /// `None`). Dropping the `ConnFulfiller` (on conn-task exit, including an
    /// executor cancel-drop) closes the fd.
    conn: Option<Conn>,
    /// This task's connection id. The host accept loop assigned it and passed
    /// the same value to `conn_new`, so the handler's `ctx.read(cid)` carries
    /// it; a mismatch is a handler bug and yields an error.
    cid: u64,
    extension_id: ServiceId,
    /// Outbound-invoke routing table — a conn task's
    /// `ctx.ask(target, msg)` looks the target up here (scoped→unscoped) and
    /// sends an `InvokeRequest` with a per-call async reply.
    invoke_routes: InvokeRoutes,
    /// Leader-forwarding context for asks that target a raft-hosted
    /// agent whose local replica is a follower.
    raft_fwd: RaftFwd,
}

impl ConnFulfiller {
    async fn fulfill(&mut self, effect: &[u8]) -> Vec<u8> {
        use crate::effects::bytestream as bs;
        use crate::effects::{
            EFFECT_ACCEPT, EFFECT_ASK, EFFECT_ASK_DISPATCH, EFFECT_CLOSE, EFFECT_LISTEN,
            EFFECT_READ, EFFECT_WRITE,
        };
        let extension_id = self.extension_id;
        match effect.first().copied() {
            // Outbound `ctx.ask` from a transport conn task.
            // Plain ASK → raw reply bytes (failure collapses to empty →
            // `Value::Unit`); dispatching ASK → status-framed so the
            // caller (the gateway) can tell a real reply from a failure.
            Some(EFFECT_ASK) => self.fulfill_ask(&effect[1..]).await,
            Some(EFFECT_ASK_DISPATCH) => self.fulfill_ask_dispatch(&effect[1..]).await,
            Some(EFFECT_READ) => {
                let Some((cid, max)) = bs::decode_read(&effect[1..]) else {
                    return bs::resp_err("read: bad request");
                };
                if cid != self.cid {
                    return bs::resp_err("read: foreign conn id in a transport connection task");
                }
                let Some(conn) = self.conn.as_mut() else {
                    return bs::resp_err("read: connection already closed");
                };
                let mut buf = alloc::vec![0u8; max.min(MAX_READ) as usize];
                // Race the read against an idle deadline so a silent / dribbling
                // peer can't park this connection task forever (slow-loris).
                let outcome: Option<std::io::Result<usize>> =
                    futures_lite::future::or(async { Some(conn.read(&mut buf).await) }, async {
                        async_io::Timer::after(READ_IDLE_TIMEOUT).await;
                        None
                    })
                    .await;
                match outcome {
                    // n == 0 → EOF → ok-empty (the handler reads `Some(empty)`).
                    Some(Ok(n)) => {
                        buf.truncate(n);
                        bs::resp_ok_bytes(&buf)
                    }
                    Some(Err(e)) => bs::resp_err(&format!("read: {e}")),
                    None => {
                        warn!(%extension_id, cid = self.cid, "transport read idle timeout");
                        bs::resp_err("read: idle timeout")
                    }
                }
            }
            Some(EFFECT_WRITE) => {
                let Some((cid, data)) = bs::decode_write(&effect[1..]) else {
                    return bs::resp_err("write: bad request");
                };
                if cid != self.cid {
                    return bs::resp_err("write: foreign conn id in a transport connection task");
                }
                let Some(conn) = self.conn.as_mut() else {
                    return bs::resp_err("write: connection already closed");
                };
                match conn.write(&data).await {
                    Ok(n) => bs::resp_ok_u32(n as u32),
                    Err(e) => bs::resp_err(&format!("write: {e}")),
                }
            }
            Some(EFFECT_CLOSE) => {
                // Idempotent: only our own cid closes our conn; a foreign id is
                // a no-op. Drop closes the fd.
                if bs::decode_close(&effect[1..]) == Some(self.cid) {
                    self.conn = None;
                }
                bs::resp_ok_empty()
            }
            Some(EFFECT_LISTEN | EFFECT_ACCEPT) => {
                error!(
                    %extension_id,
                    "transport conn task attempted listen/accept — the host owns the accept loop"
                );
                bs::resp_err(
                    "listen/accept is not available in a transport connection task \
                     (the host owns the accept loop)",
                )
            }
            other => {
                // EFFECT_FETCH / BLOB_GET / BLOB_PUT (and anything else) stay
                // rejected in v1: they take the synchronous `handle_effect` transport and
                // would block the single executor thread. (ASK is handled above
                // via the async invoke route.) Returning empty bytes makes the
                // handler's fetch/blob decode yield `None`/default, not hang.
                error!(
                    %extension_id,
                    tag = ?other,
                    "transport conn task attempted an unsupported request/reply effect \
                     (FETCH/BLOB) — deferred to a later phase"
                );
                Vec::new()
            }
        }
    }

    /// Fulfil a plain `EFFECT_ASK` from a transport connection task:
    /// the raw reply bytes the `Ask` future's `decode_reply` expects.
    /// Any failure (no route / send error / timeout / non-DONE status) degrades
    /// to empty bytes → `Value::Unit`, which the handler already tolerates —
    /// callers that must distinguish a failure use `EFFECT_ASK_DISPATCH`.
    async fn fulfill_ask(&self, rest: &[u8]) -> Vec<u8> {
        self.invoke_route(rest).await.unwrap_or_default()
    }

    /// Fulfil an `EFFECT_ASK_DISPATCH`: same routing as
    /// [`fulfill_ask`], but **status-framed** so the caller (the http-gateway)
    /// can tell a real reply (`Some`) from a dispatch failure (`None`) —
    /// `[RESP_OK][reply…]` vs `[RESP_ERR]`, the byte-stream convention. Lets a
    /// gateway render a handler panic as `502` instead of `200 null`.
    async fn fulfill_ask_dispatch(&self, rest: &[u8]) -> Vec<u8> {
        use crate::effects::bytestream as bs;
        match self.invoke_route(rest).await {
            Some(reply) => bs::resp_ok_bytes(&reply),
            None => bs::resp_err(""),
        }
    }

    /// Transport conn tasks have no inbound caller — they serve raw external
    /// (HTTP/TCP) traffic with no authenticated VOS principal — so they relay
    /// [`Caller::Unauthenticated`] (reaches only `*`/public targets via the M5
    /// gate), matching the gateway's relay posture. See [`route_invoke`].
    ///
    /// NOTE: a transport extension's declared `intra_caps` are therefore NOT a
    /// confinement boundary — there is no caller authority to bound, so the
    /// relay is always the `Unauthenticated` floor regardless of `intra_caps`.
    /// Confinement of what a transport-fronted request can reach is the *target*
    /// actor's own role gate, not the gateway's caps. (`intra_caps` bound only
    /// the actor-mode `ctx.ask_dispatch` relay, which carries a real caller.)
    async fn invoke_route(&self, rest: &[u8]) -> Option<Vec<u8>> {
        route_invoke(
            &self.invoke_routes,
            &self.raft_fwd,
            self.extension_id,
            crate::actors::Caller::Unauthenticated,
            None,
            None,
            rest,
        )
        .await
    }
}

/// Route `[target:u32 LE][payload]` through the host invoke substrate with a
/// per-call **async** reply (`ReplyChannel::Async`), awaited on the executor
/// (no blocking-pool thread, correlated per-call). `caller` + `space_role` +
/// `actor_local_role` are the relayed authority the caller already computed —
/// `Caller::Unauthenticated` (no role) for a transport conn task (no inbound
/// caller); for an actor-mode extension's `ctx.ask_dispatch`, the *bounded*
/// real caller (`resolve_relay_caller`), NOT the `Caller::Actor` bypass, so a
/// role-gated target consults the caller's capped role. Returns the unwrapped reply
/// bytes on a `STATUS_DONE`/`STATUS_YIELDED` envelope (`Some`, possibly empty
/// for a `()` return) or `None` on any failure (no route / send error / timeout
/// / non-DONE status). Shared by [`ConnFulfiller`] (transport) + [`Fulfiller`]
/// (actor-mode `EFFECT_ASK_DISPATCH`).
///
/// Raft targets get one extra move: when the target maps to a
/// raft-hosted agent (via `fwd.hosts`) and the local replica DROPS
/// the reply — a follower's commit fails NotLeader and
/// `handle_invoke_request` closes the channel — the invoke is
/// re-sent to the group's leader over libp2p. Reads never hit this
/// path (an unchanged-state commit short-circuits before the
/// propose, so followers answer them locally).
async fn route_invoke(
    invoke_routes: &InvokeRoutes,
    fwd: &RaftFwd,
    extension_id: ServiceId,
    caller: crate::actors::Caller,
    space_role: Option<u8>,
    actor_local_role: Option<u8>,
    rest: &[u8],
) -> Option<Vec<u8>> {
    if rest.len() < 4 {
        return None;
    }
    let target = u32::from_le_bytes(rest[..4].try_into().unwrap());
    let payload = rest[4..].to_vec();

    // Snapshot the forward plan up front (and clone the payload only
    // when one exists) — the local send consumes `payload`.
    let forward_plan =
        raft_forward_plan(fwd, extension_id, target).map(|rep| (rep, payload.clone()));

    // Route lookup with two-way prefix fallback against the local table:
    //
    // - **scoped→unscoped** (`target & 0xFFFF`): the registry's `resolve`
    //   returns a node-prefix-scoped id while special unscoped agents (the
    //   registry at local_id 0) register themselves bare. Mirrors
    //   `dispatch_invoke`.
    // - **unscoped→scoped** (`extension_prefix | local`): the inverse case an
    //   actor-mode extension hits — the in-`.so` `Context::id()` carries no
    //   node prefix, so the extension passes `caller_prefix = 0` to the
    //   registry's `resolve`, which then hands back an *unscoped* id; but
    //   locally-registered agents live under the host's prefix. Re-scope with
    //   the calling extension's own prefix (the host knows it even though the
    //   `.so` doesn't) so a same-space dep resolves. A 0-prefix host collapses
    //   this to the unscoped form (harmless).
    let scoped = (extension_id.0 & 0xFFFF_0000) | (target & 0xFFFF);
    let tx = {
        let map = invoke_routes.lock().ok()?;
        match map
            .get(&target)
            .or_else(|| map.get(&(target & 0xFFFF)))
            .or_else(|| map.get(&scoped))
        {
            Some(tx) => tx.clone(),
            None => {
                warn!(%extension_id, target, "ext ask: no route for target");
                return None;
            }
        }
    };

    let (reply_tx, reply_rx) = futures_channel::oneshot::channel::<Vec<u8>>();
    if tx
        .send(InvokeRequest {
            caller,
            space_role,
            actor_local_role,
            msg: payload,
            reply: ReplyChannel::Async(reply_tx),
            chain: Vec::new(),
        })
        .is_err()
    {
        return None; // target route dropped between lookup and send
    }

    // Await the reply on the executor, raced against a timeout — no thread is
    // blocked, so sibling tasks keep running while we wait. A dropped
    // sender (Canceled) is kept distinct from the timeout: it is the
    // signature of a follower refusing a write.
    let outcome = futures_lite::future::or(
        async {
            match reply_rx.await {
                Ok(env) => AskOutcome::Reply(env),
                Err(_) => AskOutcome::Canceled,
            }
        },
        async {
            async_io::Timer::after(ASK_TIMEOUT).await;
            AskOutcome::Timeout
        },
    )
    .await;

    match outcome {
        AskOutcome::Reply(env) => unwrap_invoke_envelope(&env),
        AskOutcome::Timeout => None,
        AskOutcome::Canceled => match forward_plan {
            Some((rep_id, payload)) => {
                forward_to_raft_leader(fwd, extension_id, target, rep_id, payload).await
            }
            None => None,
        },
    }
}

/// Look the ask target up in the host's raft map (same three-key
/// fallback the route lookup uses). `Some(rep_id)` means the target
/// is served by a local multi-mode Raft worker and a dropped reply
/// is worth retrying against the group's leader.
#[cfg(all(feature = "network", feature = "storage"))]
fn raft_forward_plan(fwd: &RaftFwd, extension_id: ServiceId, target: u32) -> Option<[u8; 32]> {
    let scoped = (extension_id.0 & 0xFFFF_0000) | (target & 0xFFFF);
    let map = fwd.hosts.lock().ok()?;
    map.get(&target)
        .or_else(|| map.get(&(target & 0xFFFF)))
        .or_else(|| map.get(&scoped))
        .copied()
}

#[cfg(not(all(feature = "network", feature = "storage")))]
fn raft_forward_plan(_fwd: &RaftFwd, _extension_id: ServiceId, _target: u32) -> Option<[u8; 32]> {
    None
}

/// Upper bound on the wire wait for a leader-forwarded invoke. The
/// leader's quorum wait is bounded by the 5 s propose timeout
/// (`RaftConfig::propose_timeout_ms`); 3× that covers a retry plus
/// transit without stacking anywhere near the 300 s `ASK_TIMEOUT` —
/// a wedged group should surface as a failed ask in seconds, and the
/// app-level retry owns what happens next.
#[cfg(all(feature = "network", feature = "storage"))]
const RAFT_FORWARD_TIMEOUT: Duration = Duration::from_secs(15);

/// Re-send a follower-dropped invoke to the Raft group's current
/// leader. Consults the LOCAL worker first: the forward only fires
/// when this replica is genuinely not the leader and knows who is —
/// which also filters out the other reply-drop cause (a handler
/// panic on a leader replica shows `role == Leader` and stays a
/// local failure, as before).
///
/// The reply comes back as raw bytes the remote side already
/// unwrapped (`NodeService::dispatch_invoke`), so no second unwrap
/// here. Empty bytes are indistinguishable from a remote failure and
/// collapse to `None` — raft write verbs must return a non-empty
/// reply (statuses/structs do; a bare `()` doesn't). A verbatim
/// STATUS_FORBIDDEN envelope maps to `None` for parity with the
/// local path. Caller authority on the leader is the FORWARDING
/// NODE's peer role — operators must grant member tier to a voter
/// node's peer for its forwarded writes to pass role gates.
#[cfg(all(feature = "network", feature = "storage"))]
/// Synchronous leader-forward for the agent thread's (blocking) outbound-invoke
/// path: the agent analogue of the async [`forward_to_raft_leader`] the
/// extension ask path uses. Re-sends a follower-dropped raft write to the
/// current leader and blocks on the reply.
#[cfg(all(feature = "network", feature = "storage"))]
fn agent_forward_to_raft_leader(
    fwd: &RaftFwd,
    from_id: ServiceId,
    target: u32,
    rep_id: [u8; 32],
    payload: Vec<u8>,
) -> Option<Vec<u8>> {
    let net = fwd.network.lock().ok()?.clone()?;
    let st = net.local_raft_status(&rep_id)?;
    if st.role == crate::network::RaftRole::Leader {
        return None;
    }
    let leader = st.leader_hint?;
    if leader == net.local_prefix() {
        // Hint says us but we aren't Leader — election in flight; let the
        // app-level retry pick it up.
        return None;
    }
    let peer = net.peer_for_prefix(leader)?;
    let to = ((leader as u32) << 16) | (target & 0xFFFF);
    debug!(%from_id, target, leader, "agent ask: forwarding follower-dropped raft write to leader");
    let rx = net.send_invoke(peer, from_id.0, to, Vec::new(), payload);
    match rx.recv_timeout(RAFT_FORWARD_TIMEOUT) {
        Ok(bytes)
            if !bytes.is_empty()
                && bytes.first().copied() != Some(crate::actors::run::STATUS_FORBIDDEN) =>
        {
            Some(bytes)
        }
        _ => None,
    }
}

async fn forward_to_raft_leader(
    fwd: &RaftFwd,
    extension_id: ServiceId,
    target: u32,
    rep_id: [u8; 32],
    payload: Vec<u8>,
) -> Option<Vec<u8>> {
    let net = fwd.network.lock().ok()?.clone()?;
    let st = net.local_raft_status(&rep_id)?;
    if st.role == crate::network::RaftRole::Leader {
        return None;
    }
    let leader = st.leader_hint?;
    if leader == net.local_prefix() {
        // Hint says us but the worker isn't Leader — election in
        // flight; let the app-level retry pick it up.
        return None;
    }
    let peer = net.peer_for_prefix(leader)?;
    let to = ((leader as u32) << 16) | (target & 0xFFFF);
    debug!(
        %extension_id, target, leader,
        "ext ask: forwarding follower-dropped raft write to leader"
    );
    let rx = net.send_invoke(peer, extension_id.0, to, Vec::new(), payload);
    // Poll the sync receiver cooperatively — the swarm thread fills
    // it; this task yields between polls so sibling tasks keep
    // running.
    let deadline = Instant::now() + RAFT_FORWARD_TIMEOUT;
    loop {
        match rx.try_recv() {
            Ok(bytes) => {
                if bytes.is_empty()
                    || bytes.first().copied() == Some(crate::actors::run::STATUS_FORBIDDEN)
                {
                    return None;
                }
                return Some(bytes);
            }
            Err(mpsc::TryRecvError::Disconnected) => return None,
            Err(mpsc::TryRecvError::Empty) => {
                if Instant::now() >= deadline {
                    warn!(%extension_id, target, leader, "ext ask: leader forward timed out");
                    return None;
                }
                async_io::Timer::after(Duration::from_millis(25)).await;
            }
        }
    }
}

#[cfg(not(all(feature = "network", feature = "storage")))]
async fn forward_to_raft_leader(
    _fwd: &RaftFwd,
    _extension_id: ServiceId,
    _target: u32,
    _rep_id: [u8; 32],
    _payload: Vec<u8>,
) -> Option<Vec<u8>> {
    None
}

/// Drive one actor-mode task to completion on the host executor: poll it,
/// fulfil each effect it parks on, until it is READY / PANIC. The `.so`'s
/// `task_poll` advances the future (the host never polls a `.so` future
/// directly — vtable layout is not a stable cross-artifact ABI).
async fn run_ext_task(
    instance: &mut crate::extension::ExtensionInstance<'_>,
    handle: u64,
    fulfiller: &mut Fulfiller<'_>,
) -> DispatchOutcome {
    use crate::extension::TaskOutcome;

    let extension_id = fulfiller.extension_id;

    // Free the task slot on EVERY exit path — including an unwind from a
    // panicking effect fulfilment — not just the normal READY/PANIC returns.
    // (The instance's own Drop is the ultimate backstop: it clears the whole
    // slab before the actor, so no future ever outlives the actor regardless.)
    struct TaskGuard<'i, 'p> {
        inst: &'i mut crate::extension::ExtensionInstance<'p>,
        handle: u64,
        done: bool,
    }
    impl TaskGuard<'_, '_> {
        fn finish(&mut self) {
            if !self.done {
                self.inst.drop_task(self.handle);
                self.done = true;
            }
        }
    }
    impl Drop for TaskGuard<'_, '_> {
        fn drop(&mut self) {
            if !self.done {
                self.inst.drop_task(self.handle);
            }
        }
    }

    let mut guard = TaskGuard {
        inst: instance,
        handle,
        done: false,
    };
    let mut result: Vec<u8> = Vec::new();
    let outcome = loop {
        match guard.inst.poll_task(handle, &result) {
            TaskOutcome::Ready(reply) => break DispatchOutcome::Ok(reply),
            TaskOutcome::Pending(effect) => {
                result = fulfiller.fulfill(&effect).await;
            }
            TaskOutcome::Panic => {
                error!(%extension_id, "extension: task panicked during dispatch");
                break DispatchOutcome::Err;
            }
        }
    };
    guard.finish();
    outcome
}

/// Drive one transport connection task to completion on the host executor
///. Mirror of [`run_ext_task`] but: it polls via a `Copy`
/// [`SharedInstance`] (the N conn tasks run concurrently on the one executor,
/// all sharing `&actor`), and fulfils byte effects against an **owned** [`Conn`]
/// held by a per-connection [`ConnFulfiller`] — no shared reactor map, so no
/// cross-task borrow across an `await`.
///
/// A `LiveGuard` decrements the backpressure counter on EVERY exit path:
/// normal completion, a `.so`-task panic surfaced as [`TaskOutcome::Panic`], or
/// an executor cancel-drop at shutdown (the future is dropped between awaits and
/// `Drop` still runs). On a cancel-drop the `.so`'s slab entry for `handle` is
/// NOT freed here (no `drop_task` call) — the instance's `vos_extension_drop`
/// (run by `drop_state`, after `drop(ex)`) clears the whole slab as the
/// backstop. The owned `Conn` drops with the `ConnFulfiller`, closing the fd.
#[allow(clippy::too_many_arguments)]
async fn run_conn_task(
    shared: crate::extension::SharedInstance<'_>,
    handle: u64,
    cid: u64,
    conn: Conn,
    live: std::rc::Rc<std::cell::Cell<usize>>,
    extension_id: ServiceId,
    invoke_routes: InvokeRoutes,
    raft_fwd: RaftFwd,
) {
    use crate::extension::TaskOutcome;

    struct LiveGuard(std::rc::Rc<std::cell::Cell<usize>>);
    impl Drop for LiveGuard {
        fn drop(&mut self) {
            self.0.set(self.0.get().saturating_sub(1));
        }
    }
    let _live = LiveGuard(live);

    let mut fulfiller = ConnFulfiller {
        conn: Some(conn),
        cid,
        extension_id,
        invoke_routes,
        raft_fwd,
    };
    let mut result: Vec<u8> = Vec::new();
    loop {
        match shared.poll_task(handle, &result) {
            // handle_connection returns `()`; the reply is empty and there is no
            // caller to send it to (a transport conn has no request/reply
            // envelope). Free the slab slot and end the task.
            TaskOutcome::Ready(_reply) => {
                shared.drop_task(handle);
                return;
            }
            TaskOutcome::Panic => {
                error!(%extension_id, cid, "transport: connection task panicked");
                shared.drop_task(handle);
                return;
            }
            TaskOutcome::Pending(effect) => {
                result = fulfiller.fulfill(&effect).await;
            }
        }
    }
}

/// Transport-mode extension driver. The host owns the listener
/// and accept loop, spawning one concurrent connection task per accept; the
/// extension supplies only `handle_connection(&self, ctx, conn_id)`.
///
/// Lifetime / soundness shape:
/// - The instance `state` is created here and OWNED by this frame; the accept
///   loop + every conn task hold `Copy` [`SharedInstance`] views that never
///   free it.
/// - `block_on(ex.run(accept_loop))` drives the executor; `accept_loop` spawns
///   detached conn tasks onto the same `ex`.
/// - On shutdown we `drop(ex)` FIRST (cancelling + dropping every parked conn
///   task, releasing its `*const actor` + owned `Conn`), THEN `drop_state` —
///   see the load-bearing comment at the drop site. `async-executor`'s `run()`
///   returning does not drop detached tasks; only dropping the executor does.
///
/// `drop_state` runs from [`StateGuard`] rather than a bare statement so a
/// panic unwinding out of `block_on(ex.run(..))` still frees the instance: the
/// guard is created *before* `ex`, so on both the normal path and an unwind it
/// drops *after* `ex` (locals drop in reverse declaration order), preserving the
/// load-bearing "executor gone before state freed" ordering with no UAF.
struct StateGuard<'p> {
    plugin: &'p crate::extension::ExtensionPlugin,
    state: *mut (),
}

impl Drop for StateGuard<'_> {
    fn drop(&mut self) {
        // SAFETY: `state` came from `self.plugin.create_state` and is dropped
        // exactly once (here). The executor — and thus every `SharedInstance`
        // copy referencing `state` — is already gone by the time this runs (see
        // the type doc), so this is the sole final owner.
        unsafe { self.plugin.drop_state(self.state) };
    }
}

fn run_transport_extension(
    id: ServiceId,
    plugin: crate::extension::ExtensionPlugin,
    config: ExtensionConfig,
    shutdown: Arc<AtomicBool>,
    activity: ActivityClock,
    invoke_routes: InvokeRoutes,
    raft_fwd: RaftFwd,
) -> AgentResult {
    use crate::extension::{ExtensionKind, SharedInstance};
    use std::cell::Cell;
    use std::rc::Rc;

    // The `&mut self` `new_task` path is structurally unreachable for a
    // transport instance — this driver only ever calls `conn_new`/`poll_task`/
    // `drop_task` (all via `SharedInstance`, which exposes no `new_task`).
    debug_assert_eq!(plugin.kind(), ExtensionKind::Transport);

    let Some(addr) = config.serves_addr.clone() else {
        let err = "transport extension has no serve address (ExtensionConfig::serves)";
        error!(%id, "{err}");
        return AgentResult {
            id,
            panics: 1,
            error: Some(err.into()),
        };
    };

    // Bind the listener host-side.
    let listener = match std::net::TcpListener::bind(&addr)
        .and_then(async_io::Async::<std::net::TcpListener>::new)
    {
        Ok(l) => l,
        Err(e) => {
            let err = format!("transport extension failed to bind {addr}: {e}");
            error!(%id, "{err}");
            return AgentResult {
                id,
                panics: 1,
                error: Some(err),
            };
        }
    };

    // TLS acceptor when the listener terminates TLS.
    let tls_acceptor = if config.serves_tls {
        match (
            config.tls_cert_pem.as_deref(),
            config.tls_key_pem.as_deref(),
        ) {
            (Some(cert), Some(key)) => match build_tls_acceptor(cert, key, id) {
                Some(a) => Some(a),
                None => {
                    let err = "transport extension serves_tls but the TLS acceptor failed to build";
                    error!(%id, "{err}");
                    return AgentResult {
                        id,
                        panics: 1,
                        error: Some(err.into()),
                    };
                }
            },
            _ => {
                let err = "transport extension serves_tls but no TLS cert/key configured \
                     (ExtensionConfig::tls_pem)";
                error!(%id, "{err}");
                return AgentResult {
                    id,
                    panics: 1,
                    error: Some(err.into()),
                };
            }
        }
    } else {
        None
    };

    // Clamp at use-site: the `serves_max` builder maps 0 → default, but the
    // field is public and a caller can set it to 0 directly, which would make
    // `live.get() >= 0` always true and refuse *every* connection (self-DoS).
    let max_conns = config.serves_max_conns.max(1);

    // SAFETY: create_state pairs with drop_state (via `StateGuard` below); both
    // go through the plugin's symbol pair so the allocator matches.
    let state = unsafe { plugin.create_state(&config.init_args) };
    if state.is_null() {
        let err = "transport extension: create_state returned null";
        error!(%id, "{err}");
        return AgentResult {
            id,
            panics: 1,
            error: Some(err.into()),
        };
    }
    // Free `state` on every exit path including a panic unwinding out of the
    // accept loop. Declared before `ex` so it drops after `ex` (reverse-order
    // drop), upholding the load-bearing teardown ordering. See `StateGuard`.
    let _state_guard = StateGuard {
        plugin: &plugin,
        state,
    };

    let ex = async_executor::LocalExecutor::new();
    // SAFETY: `state` is a live instance just produced by `create_state`, used
    // only on this thread, and outlives every `SharedInstance` copy — the
    // executor (hence all conn tasks holding copies) is dropped before
    // `drop_state` below. `SharedInstance` is `!Send`, never leaving this
    // thread / the `LocalExecutor`.
    let shared = unsafe { SharedInstance::new(&plugin, state) };

    // Backpressure / live-task count. Single-threaded → an `Rc<Cell>` suffices;
    // each conn task decrements via a `Drop`-guard on every exit path.
    let live = Rc::new(Cell::new(0usize));

    info!(
        %id, %addr, tls = config.serves_tls, max_conns,
        "transport: listening"
    );

    async_io::block_on(ex.run(async {
        let mut next_cid: u64 = 1;
        loop {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            // Race accept against a short timer so the loop re-checks `shutdown`
            // even while idle (`accept().await` otherwise parks forever).
            let accepted =
                futures_lite::future::or(async { Some(listener.accept().await) }, async {
                    async_io::Timer::after(Duration::from_millis(50)).await;
                    None
                })
                .await;
            let Some(accept_res) = accepted else {
                continue; // timer tick → re-check shutdown
            };
            let stream = match accept_res {
                Ok((stream, _addr)) => stream,
                Err(e) => {
                    warn!(%id, "transport accept: {e}");
                    continue;
                }
            };
            *activity.lock().unwrap() = Instant::now();

            // Mandatory backpressure: at the cap, refuse (accept-then-close)
            // rather than spawn unboundedly. Dropping the stream closes the fd.
            if live.get() >= max_conns {
                warn!(%id, max_conns, "transport: at connection cap, refusing");
                drop(stream);
                continue;
            }

            // Terminate TLS host-side for a TLS listener; the `.so` reads/writes
            // plaintext through `Conn`. Inline handshake (consistent with the
            // actor-mode accept): a slow handshake stalls only new
            // accepts, not already-spawned conn tasks.
            let conn = if let Some(acceptor) = &tls_acceptor {
                match acceptor.accept(stream).await {
                    Ok(t) => Conn::Tls(Box::new(t)),
                    Err(e) => {
                        warn!(%id, "transport tls handshake: {e}");
                        continue;
                    }
                }
            } else {
                Conn::Plain(stream)
            };

            let cid = next_cid;
            next_cid += 1;
            // Build the per-connection `handle_connection` task. The same `cid`
            // is validated by the conn's `ConnFulfiller` for every byte effect;
            // `id.0` gives the conn `Context` the agent's real (prefix-scoped)
            // ServiceId so `ctx.resolve` scopes to this node.
            let handle = shared.conn_new(cid, id.0);
            if handle == 0 {
                warn!(%id, "transport: conn_new returned 0 (no handle_connection?)");
                continue; // conn drops, closing the fd
            }
            live.set(live.get() + 1);
            ex.spawn(run_conn_task(
                shared,
                handle,
                cid,
                conn,
                live.clone(),
                id,
                invoke_routes.clone(),
                raft_fwd.clone(),
            ))
            .detach();
        }
    }));

    // ── Shutdown ordering (LOAD-BEARING) ──────────────────────────────────
    // `async-executor`'s `run()` returning does NOT drop detached tasks — they
    // are dropped only when the `LocalExecutor` itself is dropped (verified
    // async-executor 1.x). So we MUST `drop(ex)` here, BEFORE `drop_state`, to
    // cancel + drop every still-parked conn task — releasing each task's
    // `SharedInstance` copy (its `*const actor`) and its owned `Conn`. Only then
    // is `state` unreferenced and safe to free. Dropping in the other order
    // would leave parked conn tasks holding a `*const actor` into freed memory:
    // a use-after-free on the next poll.
    drop(ex);
    // `state` is freed by `_state_guard` when this frame ends (here on the
    // normal path, or during an unwind) — after `drop(ex)` either way, so the
    // executor and all `SharedInstance` copies are gone before the free.

    *activity.lock().unwrap() = Instant::now();

    AgentResult {
        id,
        panics: 0,
        error: None,
    }
}

/// Encode the host's synthetic periodic-tick message — a bare `tick` dynamic
/// `Msg` with no args, framed exactly like an inbound invoke (a `TAG_DYNAMIC`
/// byte followed by the encoded `Msg`) so the actor's macro-generated
/// `deliver` routes it to its `#[msg] async fn tick(&mut self, ctx)` handler.
fn encode_tick_payload() -> Vec<u8> {
    use crate::actors::codec::Encode;
    use crate::value::{Msg, TAG_DYNAMIC};
    let msg = Msg::new("tick");
    let encoded = msg.encode();
    let mut payload = Vec::with_capacity(1 + encoded.len());
    payload.push(TAG_DYNAMIC);
    payload.extend_from_slice(&encoded);
    payload
}

/// Dispatch a message to an actor-mode extension instance and drive it to
/// completion on the host executor `ex`. Returns the reply bytes on success or
/// `DispatchOutcome::Err` on a poisoned future (panic) or an unknown method.
#[allow(clippy::too_many_arguments)]
fn dispatch_and_poll(
    ex: &async_executor::LocalExecutor<'_>,
    instance: &mut crate::extension::ExtensionInstance<'_>,
    msg: &[u8],
    inbox: &mpsc::Receiver<Envelope>,
    outbox: &mpsc::Sender<Envelope>,
    extension_id: ServiceId,
    deferred: &mut std::collections::VecDeque<Envelope>,
    blob_fetch: &BlobFetchCtx<'_>,
    reactor: &mut ReactorTables,
    invoke_routes: &InvokeRoutes,
    intra_caps: &[crate::actors::IntraCap],
    agent_names: &AgentNames,
    raft_fwd: &RaftFwd,
) -> DispatchOutcome {
    // Actor-mode stays N=1: build exactly one root task and run it to completion
    // before the next message. Running a second root task while this one holds
    // `&mut actor` would alias — concurrency is reserved for the `&self` service
    // model (later phases).
    let handle = instance.new_task(msg);
    if handle == 0 {
        // No handler matched (unknown / undecodable method) — the old
        // POLL_ERR_NO_FUTURE / "went idle" path.
        error!(%extension_id, "extension: no handler matched message");
        return DispatchOutcome::Err;
    }

    let mut fulfiller = Fulfiller {
        inbox,
        outbox,
        extension_id,
        deferred,
        blob_fetch,
        reactor,
        invoke_routes,
        intra_caps,
        agent_names,
        raft_fwd,
    };
    // block_on(ex.run(..)) drives the root task (and any future spawned tasks)
    // on this thread — the one that owns the instance. Actor-mode spawns none.
    async_io::block_on(ex.run(run_ext_task(instance, handle, &mut fulfiller)))
}

/// Fulfill a host I/O effect. Dispatches by the effect tag byte.
fn handle_effect(
    effect: &[u8],
    inbox: &mpsc::Receiver<Envelope>,
    outbox: &mpsc::Sender<Envelope>,
    extension_id: ServiceId,
    deferred: &mut std::collections::VecDeque<Envelope>,
    blob_fetch: &BlobFetchCtx<'_>,
) -> Vec<u8> {
    use crate::effects::{EFFECT_ASK, EFFECT_BLOB_GET, EFFECT_BLOB_PUT, EFFECT_FETCH};

    if effect.is_empty() {
        return Vec::new();
    }
    let tag = effect[0];
    let rest = &effect[1..];

    match tag {
        EFFECT_ASK => {
            // [target:u32 LE][payload...]
            if rest.len() < 4 {
                return Vec::new();
            }
            let target_id = u32::from_le_bytes(rest[..4].try_into().unwrap());
            let payload = rest[4..].to_vec();
            let _ = outbox.send(Envelope {
                from: extension_id,
                to: ServiceId(target_id),
                payload,
            });
            wait_for_reply(inbox, target_id, deferred)
        }
        EFFECT_FETCH => {
            #[cfg(feature = "http")]
            {
                handle_fetch(rest)
            }
            #[cfg(not(feature = "http"))]
            {
                let _ = rest;
                crate::effects::FetchResponse::host_error(
                    "vos: built without 'http' feature — EFFECT_FETCH unavailable",
                )
                .encode()
            }
        }
        EFFECT_BLOB_GET => handle_blob_get(rest, blob_fetch),
        EFFECT_BLOB_PUT => handle_blob_put(rest, blob_fetch),
        other => {
            error!(%extension_id, tag = format!("{other:#04x}"), "extension: unknown effect tag");
            Vec::new()
        }
    }
}

/// Serve `EFFECT_BLOB_GET`. Payload =
/// `[hash: 32 bytes][hint_prefix: u16 LE]` (older callers that
/// predate the hint field still work — missing trailing bytes
/// decode as `hint_prefix = 0` = no hint). Returns the stored
/// bytes when the hash is in the local proof-blob store (hot
/// cache or disk); on miss falls through to a libp2p fan-out
/// — targeting the hinted peer first when one is supplied, then
/// every other known peer as a fallback. First peer that has the
/// blob wins; successful fetches populate both the hot cache AND
/// disk (when configured) so the next lookup short-circuits.
/// Empty bytes signal "no peer has it" — the caller surfaces it
/// as a verification reject.
fn handle_blob_get(rest: &[u8], blob_fetch: &BlobFetchCtx<'_>) -> Vec<u8> {
    if rest.len() < 32 {
        return Vec::new();
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&rest[..32]);
    let hint_prefix = if rest.len() >= 34 {
        u16::from_le_bytes([rest[32], rest[33]])
    } else {
        0
    };

    // Hot-cache hit — fast path.
    if let Some(bytes) = blob_fetch
        .proof_blobs
        .read()
        .ok()
        .and_then(|store| store.get(&hash).cloned())
    {
        return bytes;
    }

    // Disk fallback — survives restarts.
    if let Some(dir) = blob_fetch.proof_blobs_dir
        && let Ok(bytes) = std::fs::read(dir.join(proof_blob_filename(&hash)))
    {
        cache_blob(&hash, &bytes, blob_fetch);
        return bytes;
    }

    // Local miss — try the hinted peer first if any, then fan
    // out across the remaining known peers. Both legs share the
    // same `BLOB_FETCH_PEER_TIMEOUT` budget; the hint just gets
    // the first slice of it.
    #[cfg(feature = "network")]
    {
        let net = blob_fetch
            .shared_network
            .lock()
            .ok()
            .and_then(|g| g.clone());
        if let Some(net) = net {
            let deadline = Instant::now() + BLOB_FETCH_PEER_TIMEOUT;
            let hint_peer = if hint_prefix != 0 {
                net.peer_for_prefix(hint_prefix)
            } else {
                None
            };

            // Hint leg — single targeted request. Short-circuits
            // the whole call when the hint is right (the common
            // case in production: the requester knows which peer
            // produced the proof).
            if let Some(peer) = hint_peer {
                let rx = net.send_fetch_proof_blob(peer, hash);
                if let Ok(Some(bytes)) = rx.recv_timeout(BLOB_HINT_LEG_TIMEOUT) {
                    cache_blob(&hash, &bytes, blob_fetch);
                    return bytes;
                }
            }

            // Fan-out leg — race every other connected peer.
            let peers: Vec<_> = net
                .connected_peers()
                .into_iter()
                .filter(|p| Some(*p) != hint_peer)
                .collect();
            if !peers.is_empty() {
                let mut receivers: Vec<_> = peers
                    .into_iter()
                    .map(|peer| net.send_fetch_proof_blob(peer, hash))
                    .collect();
                while !receivers.is_empty() {
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    let remaining = deadline - now;
                    let poll_slice = remaining.min(Duration::from_millis(50));
                    let mut hit = None;
                    let mut still_open: Vec<_> = Vec::with_capacity(receivers.len());
                    for rx in receivers.drain(..) {
                        match rx.recv_timeout(poll_slice) {
                            Ok(Some(bytes)) => {
                                hit = Some(bytes);
                                break;
                            }
                            Ok(None) => {}
                            Err(mpsc::RecvTimeoutError::Timeout) => still_open.push(rx),
                            Err(mpsc::RecvTimeoutError::Disconnected) => {}
                        }
                    }
                    if let Some(bytes) = hit {
                        cache_blob(&hash, &bytes, blob_fetch);
                        return bytes;
                    }
                    receivers = still_open;
                }
            }
        }
    }

    // Reference `hint_prefix` so the no-network build path
    // doesn't trip the `unused_variable` lint.
    #[cfg(not(feature = "network"))]
    let _ = hint_prefix;

    Vec::new()
}

/// Serve `EFFECT_BLOB_PUT`. Payload = the raw blob bytes. Stores
/// them into the same proof-blob CAS `EFFECT_BLOB_GET` reads —
/// hot cache plus write-through disk when configured, the exact
/// tiers `VosNode::put_proof_blob` writes and under the same
/// content addressing (`proof_blob_hash`) — and returns the
/// 32-byte hash. The put is node-local; peers obtain the blob on
/// demand via the existing `handle_blob_get` fan-out (no push).
/// Store failures degrade the same way `put_proof_blob`'s do: the
/// hash is still returned and only the missing tier is lost.
fn handle_blob_put(rest: &[u8], blob_fetch: &BlobFetchCtx<'_>) -> Vec<u8> {
    let hash = proof_blob_hash(rest);
    cache_blob(&hash, rest, blob_fetch);
    hash.to_vec()
}

/// Populate hot cache + (when configured) write-through disk on
/// a successful cross-tier hit. Failures are logged and dropped
/// — the caller already has the bytes, so the local request
/// succeeds; only persistence/caching for the next request
/// degrades.
fn cache_blob(hash: &[u8; 32], bytes: &[u8], blob_fetch: &BlobFetchCtx<'_>) {
    if let Ok(mut store) = blob_fetch.proof_blobs.write() {
        store.insert(*hash, bytes.to_vec());
    }
    if let Some(dir) = blob_fetch.proof_blobs_dir {
        let path = dir.join(proof_blob_filename(hash));
        if !path.exists()
            && let Err(e) = std::fs::write(&path, bytes)
        {
            warn!(
                error = %e,
                path = %path.display(),
                "proof_blobs: disk write-through failed",
            );
        }
    }
}

/// Total wall-clock budget for the cross-node fan-out path in
/// `handle_blob_get`. STARK proofs are ~1.4 MiB on LAN today —
/// half a second is comfortable headroom for a single hop without
/// extending the federation test's overall runtime noticeably.
#[cfg(feature = "network")]
const BLOB_FETCH_PEER_TIMEOUT: Duration = Duration::from_millis(2_000);

/// Budget for the hint leg specifically — the targeted request to
/// the peer the caller named. Tight on purpose: when the hint is
/// wrong (or the hinted peer is offline) we want to fall through
/// to the fan-out quickly rather than burning the whole
/// `BLOB_FETCH_PEER_TIMEOUT` on a dead path.
#[cfg(feature = "network")]
const BLOB_HINT_LEG_TIMEOUT: Duration = Duration::from_millis(750);

/// Perform an HTTP request via ureq. Blocking; runs on the worker thread.
#[cfg(feature = "http")]
fn handle_fetch(payload: &[u8]) -> Vec<u8> {
    use crate::effects::{FetchRequest, FetchResponse, HttpMethod};

    let Some(req) = FetchRequest::decode(payload) else {
        return FetchResponse::host_error("malformed FetchRequest").encode();
    };

    let mut ureq_req = match req.method {
        HttpMethod::Get => ureq::get(&req.url),
        HttpMethod::Post => ureq::post(&req.url),
        HttpMethod::Put => ureq::put(&req.url),
        HttpMethod::Delete => ureq::delete(&req.url),
        HttpMethod::Patch => ureq::patch(&req.url),
        HttpMethod::Head => ureq::head(&req.url),
        HttpMethod::Options => ureq::request("OPTIONS", &req.url),
    };
    for (name, value) in &req.headers {
        ureq_req = ureq_req.set(name, value);
    }

    let result = if req.body.is_empty() {
        ureq_req.call()
    } else {
        ureq_req.send_bytes(&req.body)
    };

    let response = match result {
        Ok(r) => ureq_response_to(r),
        Err(ureq::Error::Status(code, r)) => {
            let mut resp = ureq_response_to(r);
            resp.status = code;
            resp
        }
        Err(e) => FetchResponse::host_error(format!("network error: {e}")),
    };

    response.encode()
}

#[cfg(feature = "http")]
fn ureq_response_to(r: ureq::Response) -> crate::effects::FetchResponse {
    use crate::effects::FetchResponse;
    let status = r.status();
    let headers: Vec<(String, String)> = r
        .headers_names()
        .into_iter()
        .filter_map(|n| r.header(&n).map(|v| (n, v.to_string())))
        .collect();
    let mut body = Vec::new();
    let _ = std::io::Read::read_to_end(&mut r.into_reader(), &mut body);
    FetchResponse {
        status,
        headers,
        body,
    }
}

// ── State persistence ───────────────────────────────────────────────

/// Pick the worker's commit strategy from its config.
///
/// Workers never get CRDT or Raft commits — they live outside the
/// deterministic universe. If a data directory is configured and the
/// `storage` feature is on, use [`LocalCommit`]; otherwise fall back
/// to [`NoCommit`] (state is held in memory only).
///
/// [`LocalCommit`]: crate::commit::LocalCommit
/// [`NoCommit`]: crate::commit::NoCommit
fn build_extension_strategy(
    config: &ExtensionConfig,
    id: ServiceId,
) -> Box<dyn crate::commit::CommitStrategy> {
    #[cfg(feature = "storage")]
    {
        if let Some(path) = config.db_path() {
            match crate::commit::LocalCommit::open(&path) {
                Ok(lc) => return Box::new(lc),
                Err(e) => {
                    warn!(%id, error = %e, "extension: failed to open storage; continuing without persistence")
                }
            }
        }
    }
    #[cfg(not(feature = "storage"))]
    {
        let _ = (config, id);
    }
    Box::new(crate::commit::NoCommit)
}

/// Serialize the worker's state and hand it to the commit strategy.
fn persist(
    strategy: &mut dyn crate::commit::CommitStrategy,
    instance: &crate::extension::ExtensionInstance<'_>,
    id: ServiceId,
) {
    let bytes = instance.save_state();
    if let Err(e) = strategy.commit_state(&bytes) {
        warn!(%id, error = %e, "extension: failed to persist state");
    }
}

/// Block until a reply arrives from a specific target service.
/// Messages from other senders are pushed to the deferred queue.
fn wait_for_reply(
    inbox: &mpsc::Receiver<Envelope>,
    target_id: u32,
    deferred: &mut std::collections::VecDeque<Envelope>,
) -> Vec<u8> {
    use std::time::Duration;
    const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

    loop {
        match inbox.recv_timeout(REPLY_TIMEOUT) {
            Ok(reply) if reply.from.0 == target_id => {
                return reply.payload;
            }
            Ok(other) => {
                // Not the reply we're waiting for — defer it
                if deferred.len() < MAX_DEFERRED {
                    deferred.push_back(other);
                } else {
                    warn!(from = %other.from, "extension: deferred queue full, dropping message");
                }
            }
            Err(_) => {
                warn!(target_id, "extension: ask timeout waiting for reply");
                return Vec::new();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_lifecycle_basic() {
        let mut node = VosNode::new();
        node.run();
        let results = node.collect();
        assert!(results.is_empty());
    }

    /// The extension-facing proof-blob CAS round trip: `EFFECT_BLOB_PUT`
    /// (`handle_blob_put`) stores under the store's own addressing
    /// (`proof_blob_hash`, i.e. `put_proof_blob` parity) and
    /// `EFFECT_BLOB_GET` (`handle_blob_get`) returns the same bytes for
    /// the returned hash.
    #[test]
    fn blob_put_round_trips_through_blob_get() {
        let store: ProofBlobStore = Arc::new(RwLock::new(HashMap::new()));
        #[cfg(feature = "network")]
        let net: SharedNetwork = Arc::new(Mutex::new(None));
        let blob_fetch = BlobFetchCtx {
            proof_blobs: &store,
            proof_blobs_dir: None,
            #[cfg(feature = "network")]
            shared_network: &net,
        };
        let bytes = b"per-segment proof bytes".to_vec();
        let reply = handle_blob_put(&bytes, &blob_fetch);
        assert_eq!(
            reply,
            proof_blob_hash(&bytes).to_vec(),
            "the put reply is the 32-byte content hash under the store's addressing"
        );
        // The get payload is `[hash:32][hint_prefix:u16 LE]`.
        let mut req = reply.clone();
        req.extend_from_slice(&0u16.to_le_bytes());
        assert_eq!(
            handle_blob_get(&req, &blob_fetch),
            bytes,
            "blob_get serves the bytes blob_put stored"
        );
    }

    #[cfg(feature = "storage")]
    #[test]
    fn consistency_byte_roundtrips() {
        for c in [
            Consistency::Ephemeral,
            Consistency::Local,
            Consistency::Crdt,
            Consistency::Raft,
        ] {
            assert_eq!(Consistency::from_u8(c.as_u8()), Some(c));
        }
        assert_eq!(Consistency::from_u8(4), None);
    }

    #[cfg(feature = "storage")]
    #[test]
    fn shareability_orders_confined_below_replicated() {
        assert!(Consistency::Ephemeral.shareability() < Consistency::Local.shareability());
        assert!(Consistency::Local.shareability() < Consistency::Crdt.shareability());
        // Crdt and Raft are both fully shared — rank-equal.
        assert_eq!(
            Consistency::Crdt.shareability(),
            Consistency::Raft.shareability()
        );
    }

    #[cfg(feature = "storage")]
    #[test]
    fn seal_pins_exact_tier_forbidding_widen_and_lateral() {
        use Consistency::*;
        // No prior seal: the request passes through unchanged.
        assert_eq!(effective_after_seal(None, Crdt), Crdt);
        assert_eq!(effective_after_seal(None, Local), Local);
        // Sealed Local: a forged/merged row claiming Crdt or Raft is
        // pinned back to Local — the immutable-local guarantee.
        assert_eq!(effective_after_seal(Some(Local), Crdt), Local);
        assert_eq!(effective_after_seal(Some(Local), Raft), Local);
        // Sealed Local stays Local; narrowing to Ephemeral is allowed.
        assert_eq!(effective_after_seal(Some(Local), Local), Local);
        assert_eq!(effective_after_seal(Some(Local), Ephemeral), Ephemeral);
        // Deliberate narrowing of a shared agent is honoured.
        assert_eq!(effective_after_seal(Some(Crdt), Local), Local);
        assert_eq!(effective_after_seal(Some(Raft), Ephemeral), Ephemeral);
        // The `Crdt`<->`Raft` lateral is now PINNED to the sealed tier:
        // a forged catalog byte can't downgrade a Raft replica to merge-anyone
        // CRDT (or upgrade the reverse). Exact re-spawn still passes.
        assert_eq!(effective_after_seal(Some(Crdt), Raft), Crdt);
        assert_eq!(effective_after_seal(Some(Raft), Crdt), Raft);
        assert_eq!(effective_after_seal(Some(Raft), Raft), Raft);
        assert_eq!(effective_after_seal(Some(Crdt), Crdt), Crdt);
    }

    #[cfg(all(feature = "network", feature = "storage"))]
    #[test]
    fn forged_registry_rows_are_rejected_at_replay() {
        // The cross-node consistency boundary, deterministically. A peer can
        // author a byte-consistent registry `CrdtEvent`, and an honest
        // node WILL merge it — `insert_node` only checks the CID, not
        // the author. The defense is at replay: `replay_dag_into_runtime`
        // feeds each merged op back through the actor as `Caller::System`
        // (the `#[msg(role)]` gate a no-op), where `authorize_op`
        // re-verifies the embedded signature.
        //
        // We hand-build a registry DAG exactly as a peer's sync would
        // deliver it — genesis `set_root`, then root-signed ops (the
        // positive controls) interleaved with forged ops signed by a
        // non-admin — inject it via the same `insert_node` path, then
        // cold-start the registry so the real replay runs. The
        // root-signed grant + install must land; the forged grant +
        // install (the forged AgentRow vector) must not. This is the
        // end-to-end counterpart to the registry's
        // `forged_*_rejected_on_system_replay_path` unit tests, which
        // exercise only the actor struct.
        use crate::actors::codec::Encode;
        use crate::commit::{Blake2b, CrdtCommit};
        use crate::effect_log::{CrdtEvent, EffectLog};
        use crate::value::{Msg, TAG_DYNAMIC};
        use ed25519_dalek::{Signer, SigningKey};
        use merkle_crdt::DagNode;
        use std::collections::BTreeSet;

        let workspace = env!("CARGO_MANIFEST_DIR");
        let elf_path = format!(
            "{workspace}/../actors/space-registry/target/riscv64em-javm/release/space_registry.elf"
        );
        let Ok(elf) = std::fs::read(&elf_path) else {
            eprintln!("SKIP: space-registry ELF not built — run: just build-registry");
            return;
        };
        let blob = grey_transpiler::link_elf(&elf).expect("registry transpiles");

        // ── Identities ──────────────────────────────────────────────
        const ADMIN: u8 = 3; // space_registry::AUTH_ROLE_ADMIN
        let root_key = SigningKey::from_bytes(&[7u8; 32]);
        let attacker_key = SigningKey::from_bytes(&[42u8; 32]);
        let peer_id_for = |pk: [u8; 32]| -> Vec<u8> {
            let mut id = vec![0x00u8, 0x24, 0x08, 0x01, 0x12, 0x20];
            id.extend_from_slice(&pk);
            id
        };
        let root_peer = peer_id_for(root_key.verifying_key().to_bytes());
        let attacker_peer = peer_id_for(attacker_key.verifying_key().to_bytes());
        let victim = vec![0xBBu8; 38];

        // auth blob = signer_peer_id || ed25519_sig(canonical_op_bytes).
        let auth_as = |key: &SigningKey, signer_peer: &[u8], op: &str, fields: &[&[u8]]| -> Vec<u8> {
            let canonical = space_registry::canonical_op_bytes(op, fields);
            let sig = key.sign(&canonical).to_bytes();
            space_registry::pack_auth(signer_peer, &sig)
        };

        // A shared program the installs pin to.
        let prog = "p";
        let ver = "1";
        let hash = vec![7u8; 32];
        let rep = vec![9u8; 32];
        let consistency = Consistency::Crdt.as_u8();

        // ── Registry op messages (bare `[TAG_DYNAMIC][Msg]`, the shape
        //    `EffectLog.msg` records — replay re-adds the caller prefix) ─
        let dyn_payload = |m: Msg| -> Vec<u8> {
            let mut p = vec![TAG_DYNAMIC];
            p.extend_from_slice(&m.encode());
            p
        };
        let grant_msg = |key: &SigningKey, signer: &[u8], who: &[u8]| {
            // First grant for each peer → epoch 1 (the canonical now binds
            // a per-peer freshness epoch; see space_registry::grant_role).
            let epoch: u64 = 1;
            dyn_payload(
                Msg::new("grant_role")
                    .with("peer_id", who.to_vec())
                    .with("role", ADMIN as u64)
                    .with("epoch", epoch)
                    .with(
                        "auth",
                        auth_as(
                            key,
                            signer,
                            "grant_role",
                            &[who, &[ADMIN], &epoch.to_le_bytes()],
                        ),
                    ),
            )
        };
        let install_msg = |key: &SigningKey, signer: &[u8], inst: &str| {
            dyn_payload(
                Msg::new("install")
                    .with("instance_name", inst.to_string())
                    .with("program_name", prog.to_string())
                    .with("program_version", ver.to_string())
                    .with("program_hash", hash.clone())
                    .with("replication_id", rep.clone())
                    .with("consistency", consistency as u64)
                    .with("install_args", Vec::<u8>::new())
                    .with("install_payloads", Vec::<u8>::new())
                    .with("network_reachable", false)
                    .with("sync_role", crate::registry::SyncFloor::Member as u64)
                    .with(
                        "auth",
                        auth_as(
                            key,
                            signer,
                            "install",
                            &[
                                inst.as_bytes(),
                                prog.as_bytes(),
                                ver.as_bytes(),
                                &hash,
                                &rep,
                                &[consistency],
                                &[],
                                &[],
                                &[0u8], // network_reachable = false
                                &[crate::registry::SyncFloor::Member as u8], // sync_role
                            ],
                        ),
                    ),
            )
        };

        let set_root = dyn_payload(Msg::new("set_root").with("root", root_peer.clone()));
        let publish = dyn_payload(
            Msg::new("publish")
                .with("name", prog.to_string())
                .with("version", ver.to_string())
                .with("hash", hash.clone())
                .with(
                    "auth",
                    auth_as(&root_key, &root_peer, "publish", &[prog.as_bytes(), ver.as_bytes(), &hash]),
                ),
        );
        let ops = [
            set_root,
            grant_msg(&root_key, &root_peer, &victim), // valid grant
            grant_msg(&attacker_key, &attacker_peer, &attacker_peer), // forged grant
            publish,
            install_msg(&root_key, &root_peer, "good"), // valid install
            install_msg(&attacker_key, &attacker_peer, "evil"), // forged install
        ];

        // ── Pre-seed the registry's redb with the DAG, exactly as a
        //    peer's sync would: `insert_node` + `compact_roots`, no
        //    committed state — so cold start replays the whole chain. ──
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let data_dir =
            std::env::temp_dir().join(format!("vos_forged_row_{}_{}", std::process::id(), stamp));
        let agents_dir = data_dir.join("agents");
        std::fs::create_dir_all(&agents_dir).unwrap();
        // db_path(ServiceId::REGISTRY) = {data_dir}/agents/{id.0:08x}.redb.
        let redb_path = agents_dir.join(format!("{:08x}.redb", ServiceId::REGISTRY.0));

        {
            let origin = [0x11u8; 32]; // a remote replica's origin
            let mut db = CrdtCommit::open(&redb_path, origin).unwrap();
            let mut prev: Option<merkle_crdt::Cid<Blake2b>> = None;
            for (seq, msg) in ops.into_iter().enumerate() {
                let event = CrdtEvent::new(origin, seq as u64, EffectLog::for_msg(msg));
                let children: BTreeSet<merkle_crdt::Cid<Blake2b>> = prev.into_iter().collect();
                let dag_node: DagNode<Blake2b, CrdtEvent> = DagNode::new(event, children);
                let cid = dag_node.cid();
                assert!(
                    db.insert_node(&cid.0, &dag_node.to_bytes()).unwrap(),
                    "node {seq} is new",
                );
                prev = Some(cid);
            }
            db.compact_roots().unwrap();
        } // drop releases the redb lock before the agent reopens it

        // ── Cold-start the registry over the seeded DAG ─────────────
        let mut node = VosNode::new();
        node.register_at_id(
            AgentConfig::new(blob)
                .with_consistency(Consistency::Crdt)
                .with_replication_id([0x11u8; 32])
                .persist(&data_dir),
            ServiceId::REGISTRY,
        );

        // Query via raw invoke (the typed `SpaceRegistryRef` can't be
        // used here — the dev-dep registry links a different vos build
        // than the crate under test, so `&node` doesn't satisfy its
        // `Invoker` bound). `peer_role` returns a `u8` (decodes as a
        // `Value`); for `agent` we compare the reply against a
        // known-`None` baseline rather than decoding `Option<AgentRow>`.
        let invoke = |m: Msg| -> Vec<u8> {
            let mut p = vec![TAG_DYNAMIC];
            p.extend_from_slice(&m.encode());
            node.invoke(ServiceId::REGISTRY, p).expect("registry reply")
        };
        let role_of = |peer: &[u8]| -> u64 {
            let bytes = invoke(Msg::new("peer_role").with("peer_id", peer.to_vec()));
            let v: crate::value::Value = crate::Decode::decode(&bytes);
            v.as_u64().expect("peer_role returns an integer")
        };
        let agent_reply = |inst: &str| invoke(Msg::new("agent").with("instance_name", inst.to_string()));
        let none_reply = agent_reply("does-not-exist"); // canonical `None` for this type

        // Positive controls: the root-signed ops survived replay —
        // proves the inject + replay pipeline is genuinely live.
        assert_eq!(role_of(&victim), ADMIN as u64, "root-signed grant must apply on replay");
        assert_ne!(
            agent_reply("good"),
            none_reply,
            "root-signed install must materialize an AgentRow on replay",
        );

        // The headline: forged ops were refused by authorize_op on the
        // System replay path, so neither row ever materializes.
        assert_eq!(
            role_of(&attacker_peer),
            0,
            "forged admin grant must be rejected at replay (AUTH_ROLE_NONE)",
        );
        assert_eq!(
            agent_reply("evil"),
            none_reply,
            "forged install (M5 AgentRow vector) must be rejected at replay",
        );

        node.shutdown();
        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn run_forever_with_idle_hook_gets_mut_node_and_can_invoke() {
        // A stand-in long-running agent: without one, the
        // all-agents-exited early-exit breaks the loop before the
        // idle hook ever fires.
        let mut node = VosNode::new();
        let stop = Arc::new(AtomicBool::new(false));
        let agent_stop = stop.clone();
        node.agents.push(AgentHandle {
            join: Some(thread::spawn(move || {
                while !agent_stop.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(5));
                }
                AgentResult {
                    id: ServiceId(1),
                    panics: 0,
                    error: None,
                }
            })),
        });

        // The hook registers a responder on its first tick (the
        // &mut access registration needs), then synchronously
        // invokes it on later ticks — the same shape an embedder's
        // spawn-reconcile uses (register_at_id + registry query).
        let mut responder: Option<ServiceId> = None;
        let mut echoed: Option<Vec<u8>> = None;
        node.run_forever_with(|n| match responder {
            None => responder = Some(n.install_invoke_responder(|msg| msg)),
            Some(id) => {
                if echoed.is_none() {
                    echoed = n.invoke(id, b"ping".to_vec());
                }
                if echoed.is_some() {
                    n.shutdown();
                }
            }
        });
        stop.store(true, Ordering::Relaxed);
        assert_eq!(echoed.as_deref(), Some(&b"ping"[..]));
    }

    #[test]
    fn has_agent_tracks_registered_ids() {
        let node = VosNode::new();
        let id = ServiceId::new(0, 0x0123);
        assert!(!node.has_agent(id));
        node.agent_info.write().unwrap().insert(
            id.0,
            AgentInfo {
                name: Some("late".into()),
                kind: crate::extension::ExtensionKind::Actor as u8,
                serves_addr: None,
                consistency: None,
                network_reachable: false,
            },
        );
        assert!(node.has_agent(id));
    }

    #[test]
    fn relay_caller_guard_is_thread_scoped_and_clears() {
        use crate::actors::{Caller, SpaceRole};
        // No dispatch in flight on this thread → no relay caller.
        assert!(current_relay_caller().is_none());

        let pc = PropagatedCaller {
            caller: Caller::Peer(vec![0xaa, 0xbb]),
            space_role: Some(SpaceRole::Developer.as_u8()),
        };
        {
            let _g = RelayCallerGuard::stamp(pc.clone());
            // invoke_fn reads the slot on the SAME thread the sidecar
            // stamped it on — exactly the sidecar → handler →
            // ask_raw → invoke_fn chain.
            let seen = current_relay_caller().expect("stamped caller visible same-thread");
            assert_eq!(seen.caller, pc.caller);
            assert_eq!(seen.space_role, pc.space_role);

            // A DIFFERENT thread must not see this thread's caller —
            // the run()/tokio threads stay isolated, so a concurrent
            // self-originated call relays as None (→ Unauthenticated),
            // never another caller's identity.
            let other = std::thread::spawn(current_relay_caller);
            assert!(other.join().unwrap().is_none());
        }
        // Guard dropped → slot cleared; the next dispatch on this
        // thread can't inherit a stale caller.
        assert!(current_relay_caller().is_none());
    }

    #[test]
    fn relay_resolves_target_names_through_the_reverse_map() {
        // R3 — the relay path resolves *any* installed actor's name
        // from the same reverse map the libp2p gate uses, superseding
        // the old registry-only `relay_target_name`. The registry seeds
        // itself…
        let node = VosNode::new();
        node.record_agent_name(ServiceId::REGISTRY, None);
        node.record_agent_name(ServiceId::new(0, 0x0444), Some("dev-project".into()));

        // Registry resolves (and still does under a node prefix — low
        // 16 bits zero).
        assert_eq!(
            node.agent_name_for(ServiceId::REGISTRY.0).as_deref(),
            Some(REGISTRY_AGENT_NAME)
        );
        assert_eq!(
            node.agent_name_for(ServiceId::new(0xBEEF, 0).0).as_deref(),
            Some(REGISTRY_AGENT_NAME)
        );
        // …and so does a non-registry installed agent — the cap for it
        // now binds instead of silently vanishing.
        assert_eq!(node.agent_name_for(0x0444).as_deref(), Some("dev-project"));
        // An unregistered id stays unresolved → matches only `*` caps.
        assert_eq!(node.agent_name_for(0x0007), None);
    }

    #[test]
    fn resolve_relay_caller_intersection_matrix() {
        use crate::actors::{Caller, IntraCap, SpaceRole};

        let admin_cap = [IntraCap::parse("space-registry:admin").unwrap()];
        let dev_cap = [IntraCap::parse("space-registry:developer").unwrap()];

        let peer = |b: &[u8]| Caller::Peer(b.to_vec());
        let pc = |c: Caller, sr: Option<SpaceRole>| PropagatedCaller {
            caller: c,
            space_role: sr.map(|r| r.as_u8()),
        };

        // 1. SECURITY CORE: no cap declared for the target → the relay
        //    has no authority → Unauthenticated (role-gated handlers
        //    refuse). Holds even for an admin caller.
        let p_admin = pc(peer(&[1]), Some(SpaceRole::Admin));
        assert_eq!(
            resolve_relay_caller(Some(&p_admin), &[], Some("space-registry")),
            (Caller::Unauthenticated, None),
            "empty caps deny every role-gated relay",
        );
        // A cap for a *different* actor doesn't apply to this target.
        assert_eq!(
            resolve_relay_caller(Some(&p_admin), &admin_cap, Some("dev-project")),
            (Caller::Unauthenticated, None),
        );

        // 2. Peer admin + admin cap → full admin relayed (transparent,
        //    identity preserved).
        let (c, sr) = resolve_relay_caller(Some(&p_admin), &admin_cap, Some("space-registry"));
        assert_eq!(c, peer(&[1]));
        assert_eq!(sr, Some(SpaceRole::Admin.as_u8()));

        // 3. Peer member + admin cap → bounded by the *caller's* own
        //    role (min(Member, Admin) = Member): no amplification.
        let p_member = pc(peer(&[2]), Some(SpaceRole::Member));
        let (c, sr) = resolve_relay_caller(Some(&p_member), &admin_cap, Some("space-registry"));
        assert_eq!(c, peer(&[2]));
        assert_eq!(sr, Some(SpaceRole::Member.as_u8()));

        // 4. Peer admin but a lower cap ceiling → bounded DOWN by the
        //    cap (min(Admin, Developer) = Developer).
        let (_, sr) = resolve_relay_caller(Some(&p_admin), &dev_cap, Some("space-registry"));
        assert_eq!(
            sr,
            Some(SpaceRole::Developer.as_u8()),
            "ceiling bounds an over-privileged caller",
        );

        // 5. No propagated caller (run()-thread / boot) → Unauthenticated
        //    even with a cap.
        assert_eq!(
            resolve_relay_caller(None, &admin_cap, Some("space-registry")),
            (Caller::Unauthenticated, None),
        );

        // 6. Unauthenticated incoming → nothing to relay.
        let p_unauth = pc(Caller::Unauthenticated, None);
        assert_eq!(
            resolve_relay_caller(Some(&p_unauth), &admin_cap, Some("space-registry")),
            (Caller::Unauthenticated, None),
        );

        // 7. Trusted incoming (System / Actor) → relayed ANONYMOUSLY
        //    (non-trusted carrier) but still capped, so the cap binds.
        for trusted in [Caller::System, Caller::Actor(ServiceId(9))] {
            let p_trusted = pc(trusted, None);
            let (c, sr) = resolve_relay_caller(Some(&p_trusted), &dev_cap, Some("space-registry"));
            assert!(
                !c.is_trusted(),
                "carrier must be non-trusted so the cap is not bypassed: {c:?}",
            );
            assert_eq!(c, Caller::Unauthenticated);
            assert_eq!(
                sr,
                Some(SpaceRole::Developer.as_u8()),
                "Admin capped to ceiling"
            );
        }

        // 8. Wildcard-role cap ("space-registry:*") → uncapped: a peer
        //    admin keeps admin.
        let any_role = [IntraCap::parse("space-registry:*").unwrap()];
        let (_, sr) = resolve_relay_caller(Some(&p_admin), &any_role, Some("space-registry"));
        assert_eq!(sr, Some(SpaceRole::Admin.as_u8()));

        // 9. Wildcard-actor cap ("*:member") applies to an unresolved
        //    target and caps the admin caller to member.
        let any_actor = [IntraCap::parse("*:member").unwrap()];
        let (_, sr) = resolve_relay_caller(Some(&p_admin), &any_actor, None);
        assert_eq!(sr, Some(SpaceRole::Member.as_u8()));

        // 10. Full wildcard ("*:*") — any role on any actor — uncaps a
        //     peer admin on both a named and an unresolved target.
        let full = [IntraCap::parse("*:*").unwrap()];
        let (c, sr) = resolve_relay_caller(Some(&p_admin), &full, Some("space-registry"));
        assert_eq!(c, peer(&[1]));
        assert_eq!(sr, Some(SpaceRole::Admin.as_u8()));
        let (_, sr) = resolve_relay_caller(Some(&p_admin), &full, None);
        assert_eq!(
            sr,
            Some(SpaceRole::Admin.as_u8()),
            "full wildcard matches unresolved targets too"
        );
    }

    #[test]
    fn extension_config_relay_and_caps_mutually_exclusive() {
        use crate::actors::IntraCap;
        let caps = || vec![IntraCap::parse("space-registry:admin").unwrap()];

        // relay_unauthenticated() clears any caps set before it — a
        // relay has no authority of its own.
        let cfg = ExtensionConfig::new("x.so")
            .with_intra_caps(caps())
            .relay_unauthenticated();
        assert!(cfg.relay_unauthenticated);
        assert!(
            cfg.intra_caps.is_empty(),
            "relay_unauthenticated must clear declared caps",
        );

        // …and with_intra_caps() after relay_unauthenticated() is a
        // no-op, so neither builder order can produce a relay that also
        // carries authority. Locks the documented invariant against a
        // future refactor dropping the guard.
        let cfg = ExtensionConfig::new("x.so")
            .relay_unauthenticated()
            .with_intra_caps(caps());
        assert!(cfg.relay_unauthenticated);
        assert!(
            cfg.intra_caps.is_empty(),
            "with_intra_caps after relay_unauthenticated must not re-add caps",
        );

        // Without the relay flag, caps are carried as declared.
        let cfg = ExtensionConfig::new("x.so").with_intra_caps(caps());
        assert!(!cfg.relay_unauthenticated);
        assert_eq!(cfg.intra_caps.len(), 1);
    }

    // ── unwrap_invoke_envelope contract ─────────────────────────
    //
    // Locks in what b112aa6 doc-corrected: STATUS_DONE and
    // STATUS_YIELDED both surface their reply bytes; everything
    // else (PANICKED, NOT_FOUND, short envelopes, malformed
    // state_len) collapses to None so gateway/host callers see
    // "no reply" rather than partial garbage.

    fn make_envelope(status: u8, state: &[u8], reply: &[u8]) -> Vec<u8> {
        // Mirrors `encode_invoke_envelope` exactly so we're not
        // testing the encoder against itself — keeps the test
        // honest if `encode_invoke_envelope` regresses.
        let mut v = Vec::with_capacity(5 + state.len() + reply.len());
        v.push(status);
        v.extend_from_slice(&(state.len() as u32).to_le_bytes());
        v.extend_from_slice(state);
        v.extend_from_slice(reply);
        v
    }

    #[test]
    fn unwrap_envelope_done_with_reply_yields_reply() {
        use crate::actors::run::STATUS_DONE;
        let env = make_envelope(STATUS_DONE, b"some-state", b"the-reply");
        assert_eq!(
            unwrap_invoke_envelope(&env).as_deref(),
            Some(&b"the-reply"[..]),
        );
    }

    #[test]
    fn unwrap_envelope_done_with_empty_reply_yields_empty() {
        use crate::actors::run::STATUS_DONE;
        let env = make_envelope(STATUS_DONE, b"state-only", b"");
        // Empty reply is meaningful: handler returned `()`.
        // Caller distinguishes `Some(empty)` (returned unit) from
        // `None` (envelope unusable).
        let r = unwrap_invoke_envelope(&env).expect("done envelope decodes");
        assert!(r.is_empty(), "empty-reply envelope must yield Some(empty)");
    }

    #[test]
    fn unwrap_envelope_yielded_surfaces_reply() {
        // YIELDED carries a post-dispatch state + the partial
        // reply so far. Host callers (gateway) just want the
        // bytes; the YIELDED-vs-DONE distinction is for
        // `decode_invoke_envelope` on the runtime side.
        use crate::actors::run::STATUS_YIELDED;
        let env = make_envelope(STATUS_YIELDED, b"yielded-state", b"partial");
        assert_eq!(
            unwrap_invoke_envelope(&env).as_deref(),
            Some(&b"partial"[..]),
        );
    }

    #[test]
    fn unwrap_envelope_panicked_yields_none() {
        // The gateway path now distinguishes panic → 502 from
        // "() return" → 200 null. That hinges on PANICKED
        // collapsing to None here.
        let env = make_envelope(crate::STATUS_PANICKED, b"", b"would-be-reply");
        assert_eq!(unwrap_invoke_envelope(&env), None);
    }

    #[test]
    fn unwrap_envelope_not_found_yields_none() {
        let env = make_envelope(crate::STATUS_NOT_FOUND, b"", b"");
        assert_eq!(unwrap_invoke_envelope(&env), None);
    }

    #[test]
    fn unwrap_envelope_too_short_yields_none() {
        // < 5 bytes can't carry status + state_len, regardless
        // of what those bytes claim.
        assert_eq!(unwrap_invoke_envelope(&[]), None);
        assert_eq!(unwrap_invoke_envelope(&[0]), None);
        assert_eq!(unwrap_invoke_envelope(&[0, 0, 0, 0]), None);
    }

    #[cfg(feature = "network")]
    #[test]
    fn forbidden_envelope_is_5_bytes_starting_with_status_forbidden() {
        // Wire-shape contract: vosx's `is_forbidden_envelope` peeks
        // for exactly this 5-byte pattern to surface
        // `ClientError::Forbidden`. If either the length or the
        // status byte drifts, the client-side detection silently
        // breaks and refusals collapse back to "transport failure"
        // again. Pin both.
        let env = forbidden_envelope();
        assert_eq!(env.len(), 5, "forbidden envelope must be exactly 5 bytes");
        assert_eq!(env[0], crate::STATUS_FORBIDDEN, "status byte mismatch");
        assert_eq!(&env[1..5], &[0, 0, 0, 0], "state_len must be zero");
    }

    #[test]
    fn unwrap_envelope_forbidden_yields_none() {
        // STATUS_FORBIDDEN belongs to the same failure family as
        // PANICKED/NOT_FOUND/OOG for `unwrap_invoke_envelope` —
        // there's no actor-produced reply to surface. Client-side
        // detection happens at a different layer (Invoker for
        // &VosNode), not here.
        let env = make_envelope(crate::STATUS_FORBIDDEN, b"", b"");
        assert_eq!(unwrap_invoke_envelope(&env), None);
    }

    // ── Tell-path forgery defense (C1 regression test) ───────
    //
    // The M7 caller-prefix protocol is the host's mechanism for
    // asserting "this dispatch is from <Caller>"; the PVM strips
    // the leading 6-byte header and trusts it. If any path
    // sends inbox-sourced bytes to the runtime *without* the
    // host's wrap, an attacker can prepend their own forged
    // header — flipping trust_flag=1 turns Caller::System on
    // and bypasses every role check.
    //
    // These tests pin the two host-side wrap shapes (replay +
    // inbox) so a refactor that drops the wrap (or flips a
    // trust flag) fails fast instead of silently re-opening the
    // attack surface.

    #[test]
    fn wrap_with_unauthenticated_prefix_layout() {
        // Inbox / Tell dispatch path must use the safe-default
        // wrap: trust_flag=0 (Unauthenticated), no role bytes.
        // Bytes 0..6 are the fixed-shape header; the original
        // payload trails verbatim.
        let inner = b"some-msg-bytes";
        let wrapped = wrap_with_unauthenticated_prefix(inner);
        assert_eq!(
            wrapped[0],
            crate::actors::lifecycle::TAG_CALLER_PREFIX,
            "header must start with TAG_CALLER_PREFIX",
        );
        assert_eq!(
            wrapped[1], 0,
            "trust_flag MUST be 0 (Unauthenticated) for inbox-sourced \
             payloads — an attacker controls the inner bytes, so \
             trust=1 would forge Caller::System",
        );
        assert_eq!(
            &wrapped[2..6],
            &[0u8; 4],
            "role flags / bytes are all zero in the safe-default wrap",
        );
        assert_eq!(
            &wrapped[6..],
            &inner[..],
            "inner payload trails the header verbatim",
        );
    }

    #[test]
    fn replay_payload_carries_recorded_caller() {
        // Replay re-runs a committed log entry under the RECORDED
        // caller prefix, so the original gate decision reproduces —
        // refused stays refused, granted stays granted. Legacy logs
        // decode as CALLER_SYSTEM, their historical replay identity.
        let inner = b"logged-msg";
        let recorded: crate::effect_log::CallerPrefix = [0, 1, 3, 0, 0];
        let wrapped = encode_replay_payload(&recorded, inner);
        assert_eq!(wrapped[0], crate::actors::lifecycle::TAG_CALLER_PREFIX);
        assert_eq!(&wrapped[1..6], &recorded[..]);
        assert_eq!(&wrapped[6..], &inner[..]);

        let legacy = encode_replay_payload(&crate::effect_log::CALLER_SYSTEM, inner);
        assert_eq!(legacy[1], 1, "legacy logs replay as trusted-System");
    }

    #[test]
    fn inbox_wrap_neutralises_forged_caller_prefix() {
        // Attacker crafts a Tell payload that *itself* starts
        // with TAG_CALLER_PREFIX and a forged trust_flag=1
        // (System). After the host wraps it with the safe
        // default, the attacker's bytes start at offset 6 — the
        // PVM's dispatch_one only strips one prefix, so the
        // attacker's bytes go to the Msg decoder, NOT to a
        // second caller-set. dispatch_one is single-pass, so
        // confirming the wrap puts the attacker's prefix at
        // offset 6 is sufficient to prove the forgery is
        // neutralised.
        let forged: Vec<u8> = std::iter::once(crate::actors::lifecycle::TAG_CALLER_PREFIX)
            .chain([1, 0, 0, 0, 0])
            .chain(b"would-be-admin-call".iter().copied())
            .collect();
        let wrapped = wrap_with_unauthenticated_prefix(&forged);
        // Host's prefix at 0..6, attacker's bytes start at 6.
        assert_eq!(wrapped[1], 0, "outer trust_flag must be 0");
        assert_eq!(
            wrapped[6],
            crate::actors::lifecycle::TAG_CALLER_PREFIX,
            "attacker's prefix byte is preserved inside as msg \
             content — dispatch_one is single-pass so this byte \
             gets treated as the first byte of the inner Msg, not \
             as another caller-prefix to strip",
        );
        // The forged trust_flag=1 byte sits at offset 7, where
        // it can only be decoded as part of a malformed Msg.
        assert_eq!(wrapped[7], 1);
    }

    #[test]
    fn unwrap_envelope_oversized_state_len_yields_none() {
        // state_len claims more bytes than the envelope holds —
        // a hostile or corrupt wire payload. Must collapse to
        // None rather than slicing out-of-bounds.
        use crate::actors::run::STATUS_DONE;
        let mut env = Vec::new();
        env.push(STATUS_DONE);
        env.extend_from_slice(&(999u32).to_le_bytes()); // claims 999B state
        env.extend_from_slice(b"only-3"); // but only 6 bytes follow
        assert_eq!(unwrap_invoke_envelope(&env), None);
    }

    #[test]
    fn invoke_forward_check_detects_cycle() {
        // Self-invoke (target already in chain).
        let chain = [1u32];
        assert_eq!(check_invoke_forward(&chain, 1), InvokeForwardCheck::Cycle);

        // A→B with B trying to call A.
        let chain = [1u32, 2u32];
        assert_eq!(check_invoke_forward(&chain, 1), InvokeForwardCheck::Cycle);

        // A→B→C, fresh target D — allowed.
        let chain = [1u32, 2u32, 3u32];
        assert_eq!(check_invoke_forward(&chain, 4), InvokeForwardCheck::Allowed);
    }

    #[test]
    fn send_reply_capped_passes_normal_payload() {
        let (tx, rx) = mpsc::channel();
        send_reply_capped(ReplyChannel::Sync(tx), vec![0u8; 100], ServiceId(1));
        let received = rx.recv().expect("received");
        assert_eq!(received.len(), 100);
    }

    #[test]
    fn send_reply_capped_drops_oversized_payload() {
        let (tx, rx) = mpsc::channel();
        // One byte over the cap.
        send_reply_capped(
            ReplyChannel::Sync(tx),
            vec![0u8; MAX_PRODUCER_REPLY + 1],
            ServiceId(1),
        );
        // Sender dropped without sending → recv yields Err(Disconnected).
        // External_invoke maps that to None, surfacing as
        // InvokeError::NotFound at the caller's PVM.
        assert!(
            rx.recv().is_err(),
            "tx should have been dropped without a send"
        );
    }

    #[test]
    fn invoke_forward_check_caps_depth() {
        let chain: Vec<u32> = (1..=MAX_CROSS_AGENT_DEPTH as u32).collect();
        assert_eq!(chain.len(), MAX_CROSS_AGENT_DEPTH);
        // At cap, even a fresh target is rejected.
        assert_eq!(
            check_invoke_forward(&chain, 9999),
            InvokeForwardCheck::DepthExceeded,
        );
        // One under cap is fine.
        let chain = &chain[..MAX_CROSS_AGENT_DEPTH - 1];
        assert_eq!(
            check_invoke_forward(chain, 9999),
            InvokeForwardCheck::Allowed,
        );
    }

    #[test]
    fn service_id_topology() {
        let id = ServiceId::new(0x00A3, 5);
        assert_eq!(id.0, 0x00A3_0005);
        assert_eq!(id.node_prefix(), 0x00A3);
        assert_eq!(id.local_id(), 5);
        assert!(id.is_on_node(0x00A3));
        assert!(!id.is_on_node(0));
        assert!(!id.is_local());
    }

    #[test]
    fn backwards_compat_local_ids() {
        let id = ServiceId(3);
        assert_eq!(id.node_prefix(), 0);
        assert_eq!(id.local_id(), 3);
        assert!(id.is_local());
        assert!(id.is_on_node(0));
    }

    #[test]
    fn registry_is_zero() {
        assert_eq!(ServiceId::REGISTRY.0, 0);
        assert_eq!(ServiceId::REGISTRY.node_prefix(), 0);
        assert_eq!(ServiceId::REGISTRY.local_id(), 0);
    }

    #[test]
    fn proof_blob_persists_across_restart() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("vos_proof_blob_{}_{}", std::process::id(), stamp));

        // Round 1: put a blob with disk backing.
        let bytes = b"persistence-test-blob".to_vec();
        let hash = {
            let node = VosNode::new().with_proof_blobs_dir(&dir);
            let h = node.put_proof_blob(bytes.clone());
            assert_eq!(node.get_proof_blob(&h).as_deref(), Some(bytes.as_slice()));
            h
        };
        // The disk file exists with the expected name.
        let path = dir.join(proof_blob_filename(&hash));
        assert!(
            path.exists(),
            "put must write through to {}",
            path.display()
        );

        // Round 2: fresh VosNode against the same dir — hot cache is
        // empty but get_proof_blob lazy-loads from disk.
        let node2 = VosNode::new().with_proof_blobs_dir(&dir);
        // Sanity: a fresh node with no disk dir wouldn't see this blob.
        let bare = VosNode::new();
        assert!(bare.get_proof_blob(&hash).is_none());
        // The disk-backed node does.
        assert_eq!(
            node2.get_proof_blob(&hash).as_deref(),
            Some(bytes.as_slice()),
            "node restart against same dir must recover blob from disk",
        );
        // And the lazy-load populated the hot cache, so a second
        // get hits the fast path (we can't observe that directly
        // here, but we can at least assert idempotence).
        assert_eq!(
            node2.get_proof_blob(&hash).as_deref(),
            Some(bytes.as_slice()),
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proof_blob_in_memory_only_without_dir() {
        // No `with_proof_blobs_dir` — hot cache only, no disk side
        // effects. Pinned so a future change doesn't silently make
        // the default behaviour write to some implicit path.
        let node = VosNode::new();
        let hash = node.put_proof_blob(b"hot-cache-only".to_vec());
        assert!(node.get_proof_blob(&hash).is_some());
        // Drop + recreate — fresh node has nothing.
        drop(node);
        let node2 = VosNode::new();
        assert!(node2.get_proof_blob(&hash).is_none());
    }

    #[test]
    fn node_assigns_global_ids() {
        let node = VosNode::with_prefix(0x0042);
        let id1 = node.alloc_id();
        let id2 = node.alloc_id();
        assert_eq!(id1, ServiceId::new(0x0042, 1));
        assert_eq!(id2, ServiceId::new(0x0042, 2));
        assert!(id1.is_on_node(0x0042));
    }

    #[test]
    #[cfg(feature = "storage")]
    fn extension_state_persists_across_restarts() {
        // EchoExtension has a `count` field that increments on each echo.
        // Run the worker, send a few messages, shut down. Restart with
        // the same redb path — the count should resume where it left off.
        let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let echo_path = workspace
            .join("target")
            .join(profile)
            .join("libecho_extension.so");
        if !echo_path.exists() {
            eprintln!("skipping: build echo-extension first");
            return;
        }

        // Use a temp data directory
        let data_dir =
            std::env::temp_dir().join(format!("vos_test_persist_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&data_dir);

        use crate::actors::codec::Encode;
        use crate::actors::value::Msg;
        let send_echo = |node: &VosNode, target: ServiceId, text: &str| {
            let msg = Msg::new("echo").with("text", text);
            let encoded = msg.encode();
            let mut payload = Vec::with_capacity(1 + encoded.len());
            payload.push(crate::actors::value::TAG_DYNAMIC);
            payload.extend_from_slice(&encoded);
            if let Some(tx) = node.routes.get(&target.0) {
                tx.send(Envelope {
                    from: ServiceId(0),
                    to: target,
                    payload,
                })
                .unwrap();
            }
        };

        // ── First run: send 2 echoes ────────────────────────────────
        {
            let mut node = VosNode::new();
            let id =
                node.register_extension(ExtensionConfig::new(echo_path.clone()).persist(&data_dir));
            send_echo(&node, id, "first");
            send_echo(&node, id, "second");
            node.run();
            let _ = node.collect();
        }

        // ── Second run: state should be restored, count starts at 2 ──
        {
            let mut node = VosNode::new();
            let id = node.register_extension(ExtensionConfig::new(echo_path).persist(&data_dir));
            send_echo(&node, id, "third");
            node.run();
            let _ = node.collect();
        }

        // Verify by opening the db directly and checking the persisted state
        use crate::commit::STATE_TABLE;
        let db_path = data_dir.join("extensions").join("echo_extension.redb");
        let db = redb::Database::open(&db_path).expect("open db");
        let txn = db.begin_read().unwrap();
        let table = txn.open_table(STATE_TABLE).unwrap();
        let bytes = table
            .get("actor")
            .unwrap()
            .expect("state present")
            .value()
            .to_vec();

        // EchoExtension has a single u32 `count` field — rkyv packs it to
        // exactly 4 bytes. After 3 echoes, count = 3.
        assert_eq!(bytes.len(), 4, "EchoExtension state is one u32");
        let count = u32::from_le_bytes(bytes.try_into().unwrap());
        assert_eq!(count, 3, "expected 3 echoes total across both runs");

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    #[cfg(feature = "http")]
    fn extension_does_http_fetch() {
        // Loads fetcher-extension and asks it to GET a URL.
        // Uses example.com which is stable and small. Skips on no network.
        let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let path = workspace
            .join("target")
            .join(profile)
            .join("libfetcher_extension.so");
        if !path.exists() {
            eprintln!("skipping extension_does_http_fetch: build fetcher-extension first");
            return;
        }

        let mut node = VosNode::new();
        let fetcher_id = node.register_extension(ExtensionConfig::new(path));

        use crate::actors::codec::Encode;
        use crate::actors::value::Msg;
        let msg = Msg::new("status").with("url", "https://example.com");
        let encoded = msg.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(crate::actors::value::TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);

        if let Some(tx) = node.routes.get(&fetcher_id.0) {
            tx.send(Envelope {
                from: ServiceId(0),
                to: fetcher_id,
                payload,
            })
            .unwrap();
        }

        node.run();
        let results = node.collect();
        for r in &results {
            assert_eq!(r.panics, 0, "fetcher worker {} panicked", r.id);
        }
    }

    #[test]
    fn extension_to_extension_ask() {
        // This test requires both echo-extension and proxy-extension to be built.
        // Run: cargo build -p echo-extension -p proxy-extension
        let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let echo_path = workspace
            .join("target")
            .join(profile)
            .join("libecho_extension.so");
        let proxy_path = workspace
            .join("target")
            .join(profile)
            .join("libproxy_extension.so");

        if !echo_path.exists() || !proxy_path.exists() {
            eprintln!("skipping extension_to_extension_ask: build workers first");
            return;
        }

        let mut node = VosNode::new();

        // Register echo worker — gets ServiceId 1
        let echo_id = node.register_extension(ExtensionConfig::new(echo_path));

        // Build init args for proxy: target = echo's ServiceId
        use crate::actors::codec::Encode;
        use crate::actors::value::{Args, Msg};
        let proxy_args = Args::new().with("target", echo_id.0);
        let proxy_id = node.register_extension(ExtensionConfig::with_args(proxy_path, &proxy_args));

        // Send a "proxy" message to the proxy worker (no target arg now —
        // the proxy already knows its target from init args)
        let msg = Msg::new("proxy").with("text", "hello via proxy");
        let encoded = msg.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(crate::actors::value::TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);

        // Inject the message by sending directly to proxy's route
        if let Some(tx) = node.routes.get(&proxy_id.0) {
            tx.send(Envelope {
                from: ServiceId(0), // pretend it's from the registry
                to: proxy_id,
                payload,
            })
            .unwrap();
        }

        // Run the node — proxy asks echo, echo replies, proxy replies back
        node.run();
        let results = node.collect();

        // Both workers should complete without panics
        for r in &results {
            assert_eq!(r.panics, 0, "worker {} panicked", r.id);
        }
    }

    /// Drive raw TCP through the host byte-stream reactor. The
    /// byte-echo extension's `serve` handler does
    /// `listen → accept → read → write → close` for one connection over the
    /// `EFFECT_LISTEN/ACCEPT/READ/WRITE/CLOSE` effects, which the host fulfils
    /// on `smol::Async` driven by `block_on(ex.run(..))`. A real TCP client
    /// connects and sees its bytes echoed — end-to-end proof the reactor +
    /// effect plumbing work. (Concurrent interleaving across connections is
    /// handled by the host accept loop + a spawned task per accept.)
    #[test]
    fn byte_echo_round_trips_through_the_host_reactor() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::time::Duration;

        let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let so = workspace
            .join("target")
            .join(profile)
            .join("libbyte_echo_extension.so");
        if !so.exists() {
            eprintln!("skipping byte_echo_round_trips: build byte-echo-extension first");
            return;
        }

        // Pick a free port by binding :0, reading the assignment, then dropping
        // it so the extension can re-bind. (Tiny TOCTOU window; fine for a test.)
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let addr = format!("127.0.0.1:{port}");

        let mut node = VosNode::new();
        // register_extension spawns the extension thread immediately, so it's
        // already looping on its inbox while this test connects below.
        let id = node.register_extension(ExtensionConfig::new(so));

        // Send `serve` via the envelope route (non-blocking); the handler will
        // bind `addr` and park on accept.
        use crate::actors::codec::Encode;
        use crate::actors::value::Msg;
        let msg = Msg::new("serve").with("addr", addr.clone());
        let encoded = msg.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(crate::actors::value::TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        node.routes
            .get(&id.0)
            .unwrap()
            .send(Envelope {
                from: ServiceId(0),
                to: id,
                payload,
            })
            .unwrap();

        // Connect, retrying until the handler's listener is up (a couple of
        // 50ms inbox poll ticks).
        let mut stream = None;
        for _ in 0..100 {
            if let Ok(s) = TcpStream::connect(&addr) {
                stream = Some(s);
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut stream = stream.expect("connect to byte-echo listener");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        // The handler reads first, then echoes — buffered either way.
        stream.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping", "byte-echo must echo the bytes back");

        drop(stream);
        let results = node.collect();
        for r in &results {
            assert_eq!(r.panics, 0, "byte-echo extension {} panicked", r.id);
        }
    }

    /// Host-terminated TLS over the byte-stream reactor. The host is
    /// configured with a self-signed cert; the byte-echo extension's
    /// `serve_tls` handler binds a `listen_tls` listener; a real rustls client
    /// completes a TLS handshake against the host, and the extension echoes the
    /// PLAINTEXT bytes back (it never sees the TLS layer). Proves the host
    /// wraps `Async<TcpStream>` in rustls transparently to the `.so`.
    #[test]
    fn byte_echo_terminates_tls_host_side() {
        use futures_rustls::rustls;
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::sync::Arc;
        use std::time::Duration;

        let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let so = workspace
            .join("target")
            .join(profile)
            .join("libbyte_echo_extension.so");
        if !so.exists() {
            eprintln!("skipping byte_echo_terminates_tls: build byte-echo-extension first");
            return;
        }

        let _ = rustls::crypto::ring::default_provider().install_default();

        // Self-signed `localhost` cert for the host to terminate TLS with.
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen self-signed");
        let cert_pem = ck.cert.pem();
        let key_pem = ck.key_pair.serialize_pem();

        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let addr = format!("127.0.0.1:{port}");

        let mut node = VosNode::new();
        let id = node.register_extension(
            ExtensionConfig::new(so).tls_pem(cert_pem.into_bytes(), key_pem.into_bytes()),
        );

        // Kick off the TLS listener via `serve_tls`.
        use crate::actors::codec::Encode;
        use crate::actors::value::Msg;
        let msg = Msg::new("serve_tls").with("addr", addr.clone());
        let encoded = msg.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(crate::actors::value::TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        node.routes
            .get(&id.0)
            .unwrap()
            .send(Envelope {
                from: ServiceId(0),
                to: id,
                payload,
            })
            .unwrap();

        // Test-only verifier that accepts the host's self-signed cert (we're
        // exercising the SERVER side, not client trust).
        #[derive(Debug)]
        struct NoVerify;
        impl rustls::client::danger::ServerCertVerifier for NoVerify {
            fn verify_server_cert(
                &self,
                _end: &rustls::pki_types::CertificateDer<'_>,
                _inter: &[rustls::pki_types::CertificateDer<'_>],
                _name: &rustls::pki_types::ServerName<'_>,
                _ocsp: &[u8],
                _now: rustls::pki_types::UnixTime,
            ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _m: &[u8],
                _c: &rustls::pki_types::CertificateDer<'_>,
                _d: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _m: &[u8],
                _c: &rustls::pki_types::CertificateDer<'_>,
                _d: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms
                    .supported_schemes()
            }
        }

        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();

        // Retry the TCP connect until the handler's listener is up.
        let mut tcp = None;
        for _ in 0..100 {
            if let Ok(s) = TcpStream::connect(&addr) {
                tcp = Some(s);
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut tcp = tcp.expect("connect to byte-echo TLS listener");
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

        let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
        let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
        tls.write_all(b"ping").unwrap();
        tls.flush().unwrap();
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping", "byte-echo must echo plaintext back over TLS");

        drop(tls);
        let results = node.collect();
        for r in &results {
            assert_eq!(r.panics, 0, "byte-echo extension {} panicked", r.id);
        }
    }

    /// The transport-mode concurrency guard. A TRANSPORT-mode
    /// extension (`tcp-echo`'s `handle_connection(&self, …)`) is driven by the
    /// HOST accept loop, which binds the listener (from `ExtensionConfig::serves`)
    /// and spawns one `&self` connection task per accept on a single cooperative
    /// executor thread. We open N concurrent TCP clients and, each round, write a
    /// distinct payload on EVERY client BEFORE reading any echo back. If the host
    /// served connections one-at-a-time-to-EOF (actor-mode N=1), `clients[1..]`
    /// would never be accepted while `clients[0]` stayed open, so these reads
    /// would hang. They don't: all N connection tasks are live and interleave —
    /// client A's later-round request is served while client B is mid-stream
    /// (open, parked between rounds). Per-connection ordering is also asserted
    /// (each client reads back exactly what it wrote, in order).
    #[test]
    fn tcp_echo_interleaves_concurrent_connections() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::time::Duration;

        let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let so = workspace
            .join("target")
            .join(profile)
            .join("libtcp_echo_extension.so");
        if !so.exists() {
            eprintln!("skipping tcp_echo_interleaves: build tcp-echo-extension first");
            return;
        }

        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let addr = format!("127.0.0.1:{port}");

        let mut node = VosNode::new();
        // Transport-mode: the HOST owns the listener (from `serves`) + accept
        // loop — no `serve` message is sent (a transport extension has no
        // inbound `#[msg]` handlers).
        let _id = node.register_extension(ExtensionConfig::new(so).serves(addr.clone(), false));

        const N: usize = 6;
        const ROUNDS: usize = 4;

        // Connect N clients, retrying until the host's listener is up.
        let mut clients: Vec<TcpStream> = Vec::with_capacity(N);
        for _ in 0..N {
            let mut s = None;
            for _ in 0..100 {
                if let Ok(c) = TcpStream::connect(&addr) {
                    s = Some(c);
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let s = s.expect("connect to tcp-echo transport listener");
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            clients.push(s);
        }

        for round in 0..ROUNDS {
            // Write a per-(client, round) payload on EVERY client first — now
            // every connection task has pending data and is parked mid-stream.
            let payloads: Vec<Vec<u8>> = (0..N)
                .map(|i| format!("c{i}-r{round}-ping").into_bytes())
                .collect();
            for (i, c) in clients.iter_mut().enumerate() {
                c.write_all(&payloads[i]).unwrap();
                c.flush().unwrap();
            }
            // THEN read every echo. All N connection tasks must be live and
            // parked-then-ready concurrently for this to complete.
            for (i, c) in clients.iter_mut().enumerate() {
                let mut buf = alloc::vec![0u8; payloads[i].len()];
                c.read_exact(&mut buf).unwrap();
                assert_eq!(
                    buf, payloads[i],
                    "client {i} round {round}: echo mismatch (interleave/ordering broken)"
                );
            }
        }

        // Close all clients → each conn task sees EOF, echoes nothing, closes.
        drop(clients);
        let results = node.collect();
        for r in &results {
            assert_eq!(
                r.panics, 0,
                "tcp-echo transport extension {} panicked",
                r.id
            );
        }
    }

    /// The transport accept loop enforces a MANDATORY
    /// backpressure cap: at `serves_max` live connection tasks it refuses
    /// further accepts (accept-then-close) rather than spawning unboundedly.
    /// We cap at 2, hold 2 connections live (proven by a round-trip, so their
    /// tasks are spawned and `live == 2 == cap`), then a 3rd connection is
    /// accepted-then-closed — the client sees EOF (0 bytes) with no echo.
    #[test]
    fn tcp_echo_backpressure_refuses_at_cap() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::time::Duration;

        let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let so = workspace
            .join("target")
            .join(profile)
            .join("libtcp_echo_extension.so");
        if !so.exists() {
            eprintln!("skipping tcp_echo_backpressure: build tcp-echo-extension first");
            return;
        }

        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let addr = format!("127.0.0.1:{port}");

        let mut node = VosNode::new();
        let _id = node.register_extension(
            ExtensionConfig::new(so)
                .serves(addr.clone(), false)
                .serves_max(2),
        );

        // Establish 2 live connections; a round-trip on each proves its task is
        // spawned (so `live` reached 2 == cap) before we probe the 3rd.
        let mut held: Vec<TcpStream> = Vec::new();
        for _ in 0..2 {
            let mut s = None;
            for _ in 0..100 {
                if let Ok(c) = TcpStream::connect(&addr) {
                    s = Some(c);
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let mut c = s.expect("connect held client");
            c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            c.write_all(b"hold").unwrap();
            c.flush().unwrap();
            let mut buf = [0u8; 4];
            c.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"hold", "held connection must echo");
            held.push(c);
        }

        // 3rd connection past the cap: accept-then-close. The kernel may complete
        // the handshake, but the host drops the stream immediately, so a read
        // sees EOF (0 bytes) / a reset — never an echo.
        let mut third = TcpStream::connect(&addr).expect("connect 3rd client");
        third
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let _ = third.write_all(b"nope"); // peer may RST; ignore.
        let mut buf = [0u8; 8];
        let n = third.read(&mut buf).unwrap_or(0);
        assert_eq!(
            n, 0,
            "a connection past the backpressure cap must be refused (EOF), not echoed"
        );

        drop(held);
        drop(third);
        let results = node.collect();
        for r in &results {
            assert_eq!(
                r.panics, 0,
                "tcp-echo transport extension {} panicked",
                r.id
            );
        }
    }

    /// A stub invoke target on its own thread: replies to each `InvokeRequest`
    /// by echoing its `msg` bytes inside a `STATUS_DONE` envelope (what the real
    /// invoke route produces). Returns the routes table + the join handle.
    /// Dropping every clone of the returned routes disconnects it so the thread
    /// exits. `reply_order` lets a test force REVERSE reply ordering to stress
    /// per-call correlation.
    #[cfg(test)]
    fn spawn_stub_invoke_target(
        target: u32,
        buffer_n: usize,
    ) -> (InvokeRoutes, std::thread::JoinHandle<()>) {
        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let (tx, rx) = mpsc::channel::<InvokeRequest>();
        routes.lock().unwrap().insert(target, tx);
        let handle = std::thread::spawn(move || {
            if buffer_n > 1 {
                // Collect `buffer_n` requests, then reply in REVERSE order — a
                // shared-inbox sender-id match would mis-route here; the per-call
                // oneshot must still deliver each reply to its own caller.
                let mut reqs: Vec<InvokeRequest> = Vec::new();
                for _ in 0..buffer_n {
                    match rx.recv() {
                        Ok(r) => reqs.push(r),
                        Err(_) => return,
                    }
                }
                for req in reqs.into_iter().rev() {
                    let env =
                        encode_invoke_envelope(crate::actors::run::STATUS_DONE, &[], &req.msg);
                    req.reply.send(env);
                }
            }
            // Then serve any further requests one-at-a-time until disconnect.
            while let Ok(req) = rx.recv() {
                let env = encode_invoke_envelope(crate::actors::run::STATUS_DONE, &[], &req.msg);
                req.reply.send(env);
            }
        });
        (routes, handle)
    }

    fn ask_effect(target: u32, payload: &[u8]) -> Vec<u8> {
        let mut effect = alloc::vec![crate::effects::EFFECT_ASK];
        effect.extend_from_slice(&target.to_le_bytes());
        effect.extend_from_slice(payload);
        effect
    }

    fn dispatch_effect(target: u32, payload: &[u8]) -> Vec<u8> {
        let mut effect = alloc::vec![crate::effects::EFFECT_ASK_DISPATCH];
        effect.extend_from_slice(&target.to_le_bytes());
        effect.extend_from_slice(payload);
        effect
    }

    /// A stub invoke target that replies to each request with a fixed status
    /// envelope (reply = the request's `msg` bytes). Lets a test drive the
    /// success (`STATUS_DONE`) vs failure (`STATUS_PANICKED`) framing of the
    /// status-framed `EFFECT_ASK_DISPATCH` path.
    #[cfg(test)]
    fn spawn_stub_invoke_target_status(
        target: u32,
        status: u8,
    ) -> (InvokeRoutes, std::thread::JoinHandle<()>) {
        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let (tx, rx) = mpsc::channel::<InvokeRequest>();
        routes.lock().unwrap().insert(target, tx);
        let handle = std::thread::spawn(move || {
            while let Ok(req) = rx.recv() {
                req.reply
                    .send(encode_invoke_envelope(status, &[], &req.msg));
            }
        });
        (routes, handle)
    }

    /// `EFFECT_ASK_DISPATCH` is **status-framed** so the
    /// gateway can tell a real reply from a dispatch failure — `[RESP_OK]
    /// [reply…]` on a `STATUS_DONE` envelope (this is what `ctx.ask_dispatch`
    /// decodes to `Some(reply)` → 200), vs `[RESP_ERR]` on any failure
    /// (`None` → 502). Locks in the panic→502 distinction the plain
    /// `EFFECT_ASK` (collapse-to-empty) path can't make.
    #[test]
    fn conn_task_dispatch_ask_frames_done_reply_with_resp_ok() {
        let target = 51u32;
        let (routes, stub) =
            spawn_stub_invoke_target_status(target, crate::actors::run::STATUS_DONE);
        let reply = async_io::block_on(async {
            let mut f = ConnFulfiller {
                conn: None,
                cid: 0,
                extension_id: ServiceId(7),
                invoke_routes: routes.clone(),
                raft_fwd: RaftFwd::default(),
            };
            f.fulfill(&dispatch_effect(target, b"payload-x")).await
        });
        assert_eq!(reply.first(), Some(&crate::effects::RESP_OK));
        assert_eq!(&reply[1..], b"payload-x");
        drop(routes);
        stub.join().unwrap();
    }

    #[test]
    fn conn_task_dispatch_ask_frames_panic_as_resp_err() {
        let target = 52u32;
        let (routes, stub) =
            spawn_stub_invoke_target_status(target, crate::actors::run::STATUS_PANICKED);
        let reply = async_io::block_on(async {
            let mut f = ConnFulfiller {
                conn: None,
                cid: 0,
                extension_id: ServiceId(7),
                invoke_routes: routes.clone(),
                raft_fwd: RaftFwd::default(),
            };
            f.fulfill(&dispatch_effect(target, b"x")).await
        });
        assert_eq!(
            reply,
            alloc::vec![crate::effects::RESP_ERR],
            "a panic envelope must frame as RESP_ERR so the gateway renders 502, not 200 null"
        );
        drop(routes);
        stub.join().unwrap();
    }

    /// A target that DROPS its reply sender (the signature of a raft
    /// follower refusing a write, or a panicking PVM handler). With no
    /// raft-forward context the ask must fail FAST — the canceled
    /// oneshot resolves immediately rather than waiting out the 300 s
    /// ASK_TIMEOUT.
    #[test]
    fn conn_task_dispatch_ask_dropped_reply_is_fast_resp_err() {
        let target = 53u32;
        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let (tx, rx) = mpsc::channel::<InvokeRequest>();
        routes.lock().unwrap().insert(target, tx);
        let stub = std::thread::spawn(move || {
            while let Ok(req) = rx.recv() {
                drop(req.reply);
            }
        });
        let started = Instant::now();
        let reply = async_io::block_on(async {
            let mut f = ConnFulfiller {
                conn: None,
                cid: 0,
                extension_id: ServiceId(7),
                invoke_routes: routes.clone(),
                raft_fwd: RaftFwd::default(),
            };
            f.fulfill(&dispatch_effect(target, b"x")).await
        });
        assert_eq!(reply, alloc::vec![crate::effects::RESP_ERR]);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a canceled reply must resolve immediately, not wait out ASK_TIMEOUT",
        );
        drop(routes);
        stub.join().unwrap();
    }

    /// Same dropped-reply target, but the hosts map claims it is
    /// raft-hosted — with no network attached the forward must bail
    /// gracefully to RESP_ERR instead of panicking or hanging.
    #[test]
    #[cfg(all(feature = "network", feature = "storage"))]
    fn conn_task_dispatch_ask_dropped_reply_raft_host_without_network_is_resp_err() {
        let target = 54u32;
        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let (tx, rx) = mpsc::channel::<InvokeRequest>();
        routes.lock().unwrap().insert(target, tx);
        let stub = std::thread::spawn(move || {
            while let Ok(req) = rx.recv() {
                drop(req.reply);
            }
        });
        let fwd = RaftFwd::default();
        fwd.hosts.lock().unwrap().insert(target, [0xAB; 32]);
        let reply = async_io::block_on(async {
            let mut f = ConnFulfiller {
                conn: None,
                cid: 0,
                extension_id: ServiceId(7),
                invoke_routes: routes.clone(),
                raft_fwd: fwd,
            };
            f.fulfill(&dispatch_effect(target, b"x")).await
        });
        assert_eq!(reply, alloc::vec![crate::effects::RESP_ERR]);
        drop(routes);
        stub.join().unwrap();
    }

    #[test]
    fn conn_task_dispatch_ask_unknown_target_is_resp_err() {
        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let reply = async_io::block_on(async {
            let mut f = ConnFulfiller {
                conn: None,
                cid: 0,
                extension_id: ServiceId(7),
                invoke_routes: routes,
                raft_fwd: RaftFwd::default(),
            };
            f.fulfill(&dispatch_effect(999, b"x")).await
        });
        assert_eq!(
            reply,
            alloc::vec![crate::effects::RESP_ERR],
            "no route must frame as RESP_ERR (→ gateway 502), not RESP_OK-empty"
        );
    }

    /// A transport conn task's `ctx.ask` (EFFECT_ASK)
    /// routes through the host invoke substrate with a per-call ASYNC (oneshot)
    /// reply, awaited on the executor, then unwrapped from the invoke envelope to
    /// the raw reply bytes the `Ask` future expects.
    #[test]
    fn conn_task_ask_routes_through_invoke_and_unwraps_reply() {
        let target: u32 = 42;
        let (routes, stub) = spawn_stub_invoke_target(target, 0);

        let payload = b"hello-ask".to_vec();
        let reply = async_io::block_on(async {
            let mut f = ConnFulfiller {
                conn: None,
                cid: 0,
                extension_id: ServiceId(7),
                invoke_routes: routes.clone(),
                raft_fwd: RaftFwd::default(),
            };
            f.fulfill(&ask_effect(target, &payload)).await
        });
        assert_eq!(
            reply, payload,
            "conn-task ask must return the unwrapped reply bytes"
        );

        drop(routes);
        stub.join().unwrap();
    }

    /// Two transport conn tasks ask CONCURRENTLY on one
    /// executor; the stub replies in REVERSE order. Each task must still receive
    /// ITS OWN reply (per-call oneshot correlation) and neither blocks the other.
    #[test]
    fn conn_task_asks_correlate_under_concurrency() {
        let target: u32 = 99;
        let (routes, stub) = spawn_stub_invoke_target(target, 2);

        let ex = async_executor::LocalExecutor::new();
        let mk = |payload: Vec<u8>| {
            let routes = routes.clone();
            async move {
                let mut f = ConnFulfiller {
                    conn: None,
                    cid: 0,
                    extension_id: ServiceId(7),
                    invoke_routes: routes,
                    raft_fwd: RaftFwd::default(),
                };
                f.fulfill(&ask_effect(target, &payload)).await
            }
        };
        let (a, b) = async_io::block_on(ex.run(async {
            let ta = ex.spawn(mk(b"AAAA".to_vec()));
            let tb = ex.spawn(mk(b"BBBB".to_vec()));
            futures_lite::future::zip(ta, tb).await
        }));
        assert_eq!(a, b"AAAA", "task A must get its OWN reply (correlation)");
        assert_eq!(b, b"BBBB", "task B must get its OWN reply (correlation)");

        drop(routes);
        stub.join().unwrap();
    }

    /// An ask to an unknown / unregistered target degrades
    /// to an empty reply (which the handler decodes as `Value::Unit`), never
    /// hangs or panics.
    #[test]
    fn conn_task_ask_unknown_target_returns_empty() {
        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let reply = async_io::block_on(async {
            let mut f = ConnFulfiller {
                conn: None,
                cid: 0,
                extension_id: ServiceId(7),
                invoke_routes: routes,
                raft_fwd: RaftFwd::default(),
            };
            f.fulfill(&ask_effect(12345, b"x")).await
        });
        assert!(
            reply.is_empty(),
            "ask to an unknown target must return empty, got {reply:?}"
        );
    }

    /// `stop_agent(id)` stops ONE transport agent — its
    /// accept loop exits and its listener closes — WITHOUT tearing down the node:
    /// a sibling transport agent keeps serving. The generic per-agent lifecycle
    /// primitive behind `vosx <agent> stop`.
    #[test]
    fn stop_agent_stops_one_transport_agent_not_the_node() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::time::Duration;

        let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let so = workspace
            .join("target")
            .join(profile)
            .join("libtcp_echo_extension.so");
        if !so.exists() {
            eprintln!("skipping stop_agent: build tcp-echo-extension first");
            return;
        }

        let free_port = || {
            TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port()
        };
        let addr_a = format!("127.0.0.1:{}", free_port());
        let addr_b = format!("127.0.0.1:{}", free_port());

        let roundtrip = |addr: &str, msg: &[u8]| -> bool {
            let Ok(mut s) = TcpStream::connect(addr) else {
                return false;
            };
            s.set_read_timeout(Some(Duration::from_secs(2))).ok();
            if s.write_all(msg).is_err() {
                return false;
            }
            let mut buf = alloc::vec![0u8; msg.len()];
            s.read_exact(&mut buf).is_ok() && buf == msg
        };
        let connect_until = |addr: &str, want_serving: bool| -> bool {
            for _ in 0..150 {
                if roundtrip(addr, b"ping") == want_serving {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            false
        };

        let mut node = VosNode::new();
        let id_a =
            node.register_extension(ExtensionConfig::new(so.clone()).serves(addr_a.clone(), false));
        let _id_b = node.register_extension(ExtensionConfig::new(so).serves(addr_b.clone(), false));

        // Both serving.
        assert!(connect_until(&addr_a, true), "agent A must come up");
        assert!(connect_until(&addr_b, true), "agent B must come up");

        // Stop ONLY A.
        assert!(node.stop_agent(id_a), "stop_agent must find A");

        // A stops serving (listener closed → round-trip fails); B keeps serving.
        assert!(
            connect_until(&addr_a, false),
            "stopped agent A must stop serving"
        );
        assert!(
            roundtrip(&addr_b, b"still-here"),
            "sibling agent B must keep serving after A is stopped (per-agent, not node-wide)"
        );

        let results = node.collect();
        for r in &results {
            assert_eq!(r.panics, 0, "transport extension {} panicked", r.id);
        }
    }

    #[test]
    fn display_format() {
        assert_eq!(format!("{}", ServiceId(3)), "svc:3");
        assert_eq!(format!("{}", ServiceId::new(0x00A3, 5)), "svc:00a3:5");
        assert_eq!(format!("{}", ServiceId::REGISTRY), "svc:0");
    }

    /// Actor-mode periodic `tick()` end-to-end. Loads echo (kind=Actor)
    /// at id 1, then heartbeat (now also kind=Actor) configured with a 100ms
    /// `tick_ms`. The host's tick timer dispatches heartbeat's `tick`, which
    /// pings echo once per tick via `ctx.ask_dispatch`. After letting it tick
    /// for ~550ms, reads echo's `count` through an `InvokeHandle` and asserts
    /// the host actually drove ≥2 ticks (real asks landed) — proving actor-mode
    /// subsumes the periodic-work pattern. Then signals shutdown and confirms
    /// every extension exits cleanly (no panic).
    #[test]
    fn tick_extension_originates_asks() {
        let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let echo_path = workspace
            .join("target")
            .join(profile)
            .join("libecho_extension.so");
        let heartbeat_path = workspace
            .join("target")
            .join(profile)
            .join("libheartbeat_extension.so");

        if !echo_path.exists() || !heartbeat_path.exists() {
            eprintln!(
                "skipping tick_extension_originates_asks: \
                 build echo-extension and heartbeat-extension first"
            );
            return;
        }

        // Heartbeat targets ServiceId(1) by default — register echo
        // first so it lands at id 1.
        let mut node = VosNode::new();
        let echo_id = node.register_extension(ExtensionConfig::new(echo_path));
        assert_eq!(
            echo_id.0, 1,
            "echo should land at id 1 (heartbeat default target)"
        );

        // The whole point of the phase: the host timer drives the ping, not a
        // self-spun `run()` loop. 100ms cadence → ~5 ticks in the window below.
        let _heartbeat_id =
            node.register_extension(ExtensionConfig::new(heartbeat_path).with_tick_ms(100));

        // Reader thread: let several ticks elapse, read echo's ping count
        // through a thread-safe invoke handle (the node itself is busy in
        // `run_forever` on this thread), stash it, then wind the node down.
        let handle = node.invoke_handle();
        let shutdown = node.shutdown_handle();
        let pings = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let reader = std::thread::spawn({
            let pings = pings.clone();
            move || {
                std::thread::sleep(std::time::Duration::from_millis(550));
                use crate::Decode;
                use crate::actors::codec::Encode;
                use crate::actors::value::{Msg, TAG_DYNAMIC, Value};
                let msg = Msg::new("count");
                let mut payload = vec![TAG_DYNAMIC];
                payload.extend_from_slice(&msg.encode());
                if let Some(reply) = handle.invoke_with_timeout(
                    ServiceId(1),
                    payload,
                    std::time::Duration::from_secs(2),
                ) {
                    let n = match <Value as Decode>::try_decode(&reply) {
                        Some(Value::U32(n)) => n,
                        Some(Value::U64(n)) => n as u32,
                        _ => 0,
                    };
                    pings.store(n, std::sync::atomic::Ordering::Relaxed);
                }
                shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        });

        node.run_forever();
        reader.join().expect("reader thread");
        let results = node.collect();
        for r in &results {
            assert_eq!(r.panics, 0, "extension {} panicked: {:?}", r.id, r.error);
        }
        let pings = pings.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            pings >= 2,
            "host tick timer should have driven ≥2 heartbeat→echo pings in ~550ms @100ms; \
             echo.count = {pings}"
        );
    }

    // ── R1: host-side local_id → name reverse map ──────────────────

    #[test]
    fn local_id_of_masks_to_low_16_bits() {
        assert_eq!(local_id_of(0x00A3_0123), 0x0123);
        assert_eq!(local_id_of(0xFFFF_BEEF), 0xBEEF);
        assert_eq!(local_id_of(ServiceId::REGISTRY.0), 0);
    }

    #[test]
    fn with_name_sets_config_name() {
        assert_eq!(
            AgentConfig::new(Vec::new())
                .with_name("counter")
                .name
                .as_deref(),
            Some("counter")
        );
        assert_eq!(
            ExtensionConfig::new("plugin.so")
                .with_name("gateway")
                .name
                .as_deref(),
            Some("gateway")
        );
        // Default: anonymous, so the reverse map simply gets no row.
        assert_eq!(AgentConfig::new(Vec::new()).name, None);
        assert_eq!(ExtensionConfig::new("plugin.so").name, None);
    }

    #[test]
    fn record_agent_name_populates_and_resolves_prefix_independently() {
        let node = VosNode::with_prefix(0x0042);
        node.record_agent_name(ServiceId::new(0x0042, 0x0321), Some("dev-project".into()));
        // Resolvable by the full prefix-scoped id…
        assert_eq!(
            node.agent_name_for(ServiceId::new(0x0042, 0x0321).0)
                .as_deref(),
            Some("dev-project")
        );
        // …and by any value sharing the low 16 bits (a replica of the
        // same instance on another node reuses the entry).
        assert_eq!(node.agent_name_for(0x0321).as_deref(), Some("dev-project"));
        assert_eq!(
            node.agent_name_for(0xBEEF_0321).as_deref(),
            Some("dev-project")
        );
        // An id this node never registered → None (deny-by-omission).
        assert_eq!(node.agent_name_for(0x0999), None);
    }

    #[test]
    fn record_agent_name_seeds_registry_name_without_explicit_name() {
        // vosx registers the registry from a bare AgentConfig (name =
        // None); the well-known registry id still resolves so the gate
        // can treat it uniformly through the map.
        let node = VosNode::new();
        node.record_agent_name(ServiceId::REGISTRY, None);
        assert_eq!(
            node.agent_name_for(ServiceId::REGISTRY.0).as_deref(),
            Some(REGISTRY_AGENT_NAME)
        );
    }

    #[test]
    fn record_agent_name_non_registry_without_name_is_noop() {
        let node = VosNode::new();
        node.record_agent_name(ServiceId::new(0, 0x0500), None);
        assert_eq!(node.agent_name_for(0x0500), None);
    }

    #[test]
    fn instance_name_collision_is_last_writer_wins() {
        // The map keys on the local half only, so two records that share
        // a local id resolve last-writer-wins. This single rule covers
        // both real cases: (a) two different node prefixes carrying the
        // same instance's local id — the cross-node replica path, where
        // both names are identical so the outcome is moot; and (b) two
        // *different* names that hash-collide into the same ~15-bit
        // local on one node — where the survivor also owns the (single)
        // route, so the map never points at a name whose route a
        // different live actor holds. The losing name's actor-local
        // grant is simply dropped (availability), never applied to
        // another actor. Distinct prefixes are used here so the assert
        // is unambiguous; record_agent_name also WARNs on the overwrite.
        let node = VosNode::new();
        node.record_agent_name(ServiceId::new(0x0001, 0x0300), Some("alpha".into()));
        node.record_agent_name(ServiceId::new(0x0002, 0x0300), Some("beta".into()));
        assert_eq!(node.agent_name_for(0x0300).as_deref(), Some("beta"));
    }

    // ── R2: libp2p actor-local probe generalised beyond the registry ──

    /// The host now resolves *any* installed agent's name from the
    /// reverse map and probes its actor-local grant — closing I1, where
    /// an operator's `--in <agent>` grant for a non-registry target was
    /// silently dropped. Drives the real `dispatch_invoke` against a
    /// mock registry (records the probed name) and a target sink
    /// (captures the delivered `actor_local_role`).
    #[cfg(feature = "network")]
    #[test]
    fn dispatch_probes_actor_local_grant_for_any_installed_agent() {
        use crate::actors::codec::{Decode, Encode};
        use crate::actors::run::STATUS_DONE;
        use crate::network::NetworkService;
        use crate::value::{Msg, TAG_DYNAMIC, Value};

        let target = ServiceId::new(0, 0x0444);
        const TARGET_NAME: &str = "dev-project";
        const ACTOR_LOCAL_ROLE: u8 = 3; // Admin grant on that actor.

        // Mock registry on route 0: answers the peer_role + actor_role
        // probes, recording which agent_name the actor-local probe asked
        // about.
        let (reg_tx, reg_rx) = mpsc::channel::<InvokeRequest>();
        let probed: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let probed_w = probed.clone();
        let reg = thread::spawn(move || {
            while let Ok(req) = reg_rx.recv() {
                // payload = [TAG_DYNAMIC] ++ rkyv(Msg)
                let msg = <Msg as Decode>::try_decode(&req.msg[1..]).expect("decode probe");
                let role = match msg.name.as_str() {
                    "actor_role" => {
                        probed_w
                            .lock()
                            .unwrap()
                            .push(msg.args.get_str("agent_name").unwrap_or_default());
                        ACTOR_LOCAL_ROLE
                    }
                    _ => AUTH_ROLE_NONE, // peer_role and anything else
                };
                let reply = encode_invoke_envelope(STATUS_DONE, &[], &Value::U8(role).encode());
                let _ = req.reply.send(reply);
            }
        });

        // Target sink: capture the actor_local_role the host delivered,
        // then reply so dispatch_invoke returns.
        let (tgt_tx, tgt_rx) = mpsc::channel::<InvokeRequest>();
        let delivered: Arc<Mutex<Option<Option<u8>>>> = Arc::new(Mutex::new(None));
        let delivered_w = delivered.clone();
        let sink = thread::spawn(move || {
            if let Ok(req) = tgt_rx.recv() {
                *delivered_w.lock().unwrap() = Some(req.actor_local_role);
                let _ = req
                    .reply
                    .send(encode_invoke_envelope(STATUS_DONE, &[], &[]));
            }
        });

        let mut routes = HashMap::new();
        routes.insert(ServiceId::REGISTRY.0, reg_tx);
        routes.insert(target.0, tgt_tx);
        let mut names = HashMap::new();
        names.insert(local_id_of(target.0), TARGET_NAME.to_string());

        let service = NodeService {
            invoke_routes: Arc::new(Mutex::new(routes)),
            agent_names: Arc::new(std::sync::RwLock::new(names)),
            agent_shutdown: Arc::new(Mutex::new(HashMap::new())),
            agent_info: Arc::new(std::sync::RwLock::new(HashMap::new())),
            #[cfg(feature = "storage")]
            replicas: Arc::new(Mutex::new(HashMap::new())),
            manifest: Arc::new(OnceLock::new()),
            proof_blobs: Arc::new(RwLock::new(HashMap::new())),
            proof_blobs_dir: None,
            operator_peer: None,
            #[cfg(feature = "storage")]
            sync_floor_cache: Arc::new(RwLock::new(HashMap::new())),
        };

        let peer = libp2p::PeerId::random();
        let mut payload = vec![TAG_DYNAMIC];
        payload.extend_from_slice(&Msg::new("do_admin_thing").encode());
        let _ = service.dispatch_invoke(Some(peer), 0, target.0, vec![], payload);

        // The actor-local probe was issued for the TARGET's name — not
        // the hardcoded registry name — and only once.
        assert_eq!(
            probed.lock().unwrap().as_slice(),
            &[TARGET_NAME.to_string()],
            "actor-local grant must be probed for the resolved target name"
        );
        // …and the resolved grant byte reached the target actor.
        assert_eq!(
            *delivered.lock().unwrap(),
            Some(Some(ACTOR_LOCAL_ROLE)),
            "host must deliver the actor-local override to the target"
        );

        drop(service); // close the senders so the mock threads exit.
        reg.join().unwrap();
        sink.join().unwrap();
    }

    /// The locality boundary: a node-confined agent (the messenger runs
    /// `consistency = "local"`, holding MLS keys + CSPRNG seed + decrypted
    /// plaintext) is reachable through the network dispatch path ONLY by this
    /// daemon's own operator — even though its route is registered and its
    /// name-derived ServiceId is computable by any peer. A non-operator peer
    /// (including a remote admin) is refused; a replicated agent (`Crdt`/
    /// `Raft`) stays reachable by anyone.
    #[test]
    #[cfg(feature = "network")]
    fn dispatch_invoke_gates_node_confined_agent_to_operator() {
        use crate::actors::codec::Encode;
        use crate::actors::run::STATUS_DONE;
        use crate::network::NetworkService;
        use crate::value::{Msg, TAG_DYNAMIC, Value};

        let target = ServiceId::new(0x00ab, 0x0123);

        // Drive one `dispatch_invoke` from `caller` against a target whose
        // AgentInfo carries `consistency`, with the daemon's `operator_peer`
        // set to `operator`. Report whether the agent actually received the
        // request and what the caller got back.
        let run = |consistency: Option<Consistency>,
                   operator: Option<libp2p::PeerId>,
                   caller: libp2p::PeerId|
         -> (bool, Vec<u8>) {
            let (tgt_tx, tgt_rx) = mpsc::channel::<InvokeRequest>();
            let received = Arc::new(AtomicBool::new(false));
            let received_w = received.clone();
            let sink = thread::spawn(move || {
                if let Ok(req) = tgt_rx.recv() {
                    received_w.store(true, Ordering::Relaxed);
                    let _ = req
                        .reply
                        .send(encode_invoke_envelope(STATUS_DONE, &[], &Value::U8(7).encode()));
                }
            });
            let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::from([(target.0, tgt_tx)])));
            let info: AgentInfos = Arc::new(std::sync::RwLock::new(HashMap::from([(
                target.0,
                AgentInfo {
                    name: Some("messenger".into()),
                    kind: crate::extension::ExtensionKind::Actor as u8,
                    serves_addr: None,
                    consistency,
                    network_reachable: false,
                },
            )])));
            let mut service =
                lifecycle_service(routes, Arc::new(Mutex::new(HashMap::new())), info);
            service.operator_peer = operator.map(|p| p.to_bytes());
            let mut payload = vec![TAG_DYNAMIC];
            payload.extend_from_slice(&Msg::new("history").encode());
            let reply = service.dispatch_invoke(Some(caller), 0, target.0, vec![], payload);
            // Drop the service (and thus the route's sender) so a sink the
            // gate skipped unblocks from `recv` and the thread can join.
            drop(service);
            let got = received.load(Ordering::Relaxed);
            sink.join().unwrap();
            (got, reply)
        };

        let operator = libp2p::PeerId::random();
        let other = libp2p::PeerId::random();

        // Confined (`Local`) called by the operator: admitted — the agent
        // receives the call and its reply rides back. This is the operator
        // driving their own device-local messenger via `vosx messenger …`.
        let (op_received, op_reply) = run(Some(Consistency::Local), Some(operator), operator);
        assert!(
            op_received,
            "the device operator must reach its own node-confined agent"
        );
        assert!(
            !op_reply.is_empty(),
            "the confined agent's reply must ride back to the operator"
        );

        // Confined called by a NON-operator peer (e.g. a remote admin): the
        // gate fires before routing — the agent never sees the call and the
        // peer gets an empty, no-such-agent reply (no existence oracle).
        let (other_received, other_reply) = run(Some(Consistency::Local), Some(operator), other);
        assert!(
            !other_received,
            "a non-operator peer must not reach a node-confined agent"
        );
        assert!(
            other_reply.is_empty(),
            "a refused confined invoke must reply empty"
        );

        // Confined with NO operator recorded (`operator_peer = None`): fail
        // closed — even though `caller` would otherwise look like the only
        // identity around, an unset operator admits nobody.
        let (unset_received, _) = run(Some(Consistency::Local), None, operator);
        assert!(
            !unset_received,
            "an unset operator must admit no one to a confined agent"
        );

        // Ephemeral is confined too — a non-operator is refused.
        let (ephemeral_received, _) = run(Some(Consistency::Ephemeral), Some(operator), other);
        assert!(
            !ephemeral_received,
            "a non-operator must not reach an ephemeral agent"
        );

        // Replicated (`Crdt`): no gate — the request reaches the agent and
        // its reply is forwarded back even for a non-operator peer.
        let (crdt_received, crdt_reply) = run(Some(Consistency::Crdt), Some(operator), other);
        assert!(
            crdt_received,
            "a replicated agent must stay reachable over the network"
        );
        assert!(
            !crdt_reply.is_empty(),
            "the replicated agent's reply must be forwarded back"
        );
    }

    /// Private-replica read gate. A bare-`#[msg]` READ on a `Private`-floor
    /// replica is served over the network only to a space member; a WRITE,
    /// and any method on a non-private agent, is left to the normal path.
    #[test]
    #[cfg(all(feature = "network", feature = "storage"))]
    fn dispatch_invoke_gates_private_replica_reads_to_members() {
        use crate::actors::codec::Encode;
        use crate::actors::run::STATUS_DONE;
        use crate::network::NetworkService;
        use crate::registry::SyncFloor;
        use crate::value::{Msg, TAG_DYNAMIC, Value};

        let target = ServiceId::new(0x00ab, 0x0150);

        // Drive one dispatch_invoke of `method` against a target the host knows
        // as `agent_name`, with the stub registry granting the caller `role`.
        // Report whether the target agent actually received the request.
        let run = |agent_name: &str, method: &str, role: u8| -> bool {
            let (routes, _reg) = spawn_stub_peer_role_registry(role);
            let (tgt_tx, tgt_rx) = mpsc::channel::<InvokeRequest>();
            routes.lock().unwrap().insert(target.0, tgt_tx);
            let received = Arc::new(AtomicBool::new(false));
            let received_w = received.clone();
            let sink = thread::spawn(move || {
                if let Ok(req) = tgt_rx.recv() {
                    received_w.store(true, Ordering::Relaxed);
                    let _ = req
                        .reply
                        .send(encode_invoke_envelope(STATUS_DONE, &[], &Value::U8(1).encode()));
                }
            });
            let names = Arc::new(std::sync::RwLock::new(HashMap::from([(
                local_id_of(target.0),
                agent_name.to_string(),
            )])));
            let mut svc = lifecycle_service(
                routes,
                Arc::new(Mutex::new(HashMap::new())),
                Arc::new(std::sync::RwLock::new(HashMap::new())),
            );
            svc.agent_names = names;
            // Seed the floor directly (the stub registry only answers the
            // peer_role probe, not agent()): `msg-*` names are Private, others
            // Public — exercising the gate itself, not floor resolution.
            let floor = if agent_name.starts_with("msg-") {
                SyncFloor::Private
            } else {
                SyncFloor::Public
            };
            svc.sync_floor_cache
                .write()
                .unwrap()
                .insert(agent_name.to_string(), (floor, Instant::now()));
            let peer = libp2p::PeerId::random();
            let mut payload = vec![TAG_DYNAMIC];
            payload.extend_from_slice(&Msg::new(method).encode());
            let _ = svc.dispatch_invoke(Some(peer), 0, target.0, vec![], payload);
            drop(svc);
            let got = received.load(Ordering::Relaxed);
            sink.join().unwrap();
            got
        };

        // Private (`msg-`) READ from a NON-member: refused before routing.
        assert!(
            !run("msg-general-log", "history", AUTH_ROLE_NONE),
            "a non-member must not read a private msg- replica"
        );
        // Private READ from a space member (READONLY): reaches the agent.
        assert!(
            run("msg-general-log", "history", AUTH_ROLE_READONLY),
            "a space member may read a private msg- replica"
        );
        // Private WRITE (`post`) is NOT gated here — it reaches the agent even
        // from a non-member; the actor's own `#[msg(role)]` check decides.
        assert!(
            run("msg-general-log", "post", AUTH_ROLE_NONE),
            "writes are not gated here — they carry the actor's own role check"
        );
        // A non-private agent's read is never gated.
        assert!(
            run("app-counter", "history", AUTH_ROLE_NONE),
            "only msg- replicas are gated"
        );
    }

    /// Raft-join admission probe: `raft_join_authorized` consults the
    /// registry's `node_role` and admits ONLY the VOTER sentinel. An
    /// unenrolled prefix (0), an observer (2), or an unreachable registry
    /// all deny — so a peer an admin never enrolled cannot become a voter.
    #[test]
    #[cfg(feature = "network")]
    fn raft_join_authorized_only_for_enrolled_voter() {
        use crate::network::NetworkService;
        // `reply = Some(b)` stands in for the registry's node_role byte;
        // `None` models no registry route at all (fail closed).
        let check = |reply: Option<u8>| -> bool {
            let routes: InvokeRoutes = match reply {
                Some(b) => spawn_stub_peer_role_registry(b).0,
                None => Arc::new(Mutex::new(HashMap::new())),
            };
            let svc = lifecycle_service(
                routes,
                Arc::new(Mutex::new(HashMap::new())),
                Arc::new(std::sync::RwLock::new(HashMap::new())),
            );
            svc.raft_join_authorized(0x00ab)
        };
        assert!(check(Some(NODE_ROLE_REPLY_VOTER)), "enrolled VOTER is admitted");
        assert!(!check(Some(0)), "an unenrolled prefix is refused");
        assert!(!check(Some(2)), "an OBSERVER is refused");
        assert!(!check(None), "an unreachable registry fails closed");
    }

    /// A stub registry on route 0 that answers the `peer_role` probe with a
    /// fixed role byte — so the lifecycle interceptor's `lookup_caller_role`
    /// gate sees a known grant. Returns (routes, join handle).
    #[cfg(feature = "network")]
    fn spawn_stub_peer_role_registry(role: u8) -> (InvokeRoutes, thread::JoinHandle<()>) {
        use crate::actors::codec::Encode;
        use crate::value::Value;
        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let (tx, rx) = mpsc::channel::<InvokeRequest>();
        routes.lock().unwrap().insert(ServiceId::REGISTRY.0, tx);
        let handle = thread::spawn(move || {
            while let Ok(req) = rx.recv() {
                let reply = encode_invoke_envelope(
                    crate::actors::run::STATUS_DONE,
                    &[],
                    &Value::U8(role).encode(),
                );
                let _ = req.reply.send(reply);
            }
        });
        (routes, handle)
    }

    /// A stub registry that answers `peer_role` and `node_role` with
    /// DIFFERENT bytes — so a test can model a peer that is enrolled as a
    /// node but holds no auth grant (or vice versa).
    #[cfg(feature = "network")]
    fn spawn_stub_role_registry(
        peer_role: u8,
        node_role: u8,
    ) -> (InvokeRoutes, thread::JoinHandle<()>) {
        use crate::actors::codec::Encode;
        use crate::value::Value;
        let routes: InvokeRoutes = Arc::new(Mutex::new(HashMap::new()));
        let (tx, rx) = mpsc::channel::<InvokeRequest>();
        routes.lock().unwrap().insert(ServiceId::REGISTRY.0, tx);
        let handle = thread::spawn(move || {
            while let Ok(req) = rx.recv() {
                let byte = match intercepted_method_name(&req.msg).as_deref() {
                    Some("node_role") => node_role,
                    _ => peer_role,
                };
                let reply = encode_invoke_envelope(
                    crate::actors::run::STATUS_DONE,
                    &[],
                    &Value::U8(byte).encode(),
                );
                let _ = req.reply.send(reply);
            }
        });
        (routes, handle)
    }

    /// The `Member` sync floor admits a peer that holds a space read grant
    /// OR is an enrolled node (a voter/observer is a space member) — the
    /// latter unwedges the join→sync→grant bootstrap order. A stranger
    /// (no grant, not enrolled) and an anonymous caller are refused.
    #[test]
    #[cfg(all(feature = "network", feature = "storage"))]
    fn sync_serve_allowed_member_admits_grants_and_enrolled_nodes() {
        use crate::registry::SyncFloor;
        let peer = libp2p::PeerId::random();
        let check = |peer_role: u8, node_role: u8| -> bool {
            let (routes, _reg) = spawn_stub_role_registry(peer_role, node_role);
            let svc = lifecycle_service(
                routes,
                Arc::new(Mutex::new(HashMap::new())),
                Arc::new(std::sync::RwLock::new(HashMap::new())),
            );
            // Seed the floor so resolve_sync_floor returns Member for the
            // app agent without an `agent()` probe against the stub.
            svc.sync_floor_cache
                .write()
                .unwrap()
                .insert("counter".to_string(), (SyncFloor::Member, Instant::now()));
            svc.sync_serve_allowed(Some(&peer), "counter")
        };
        assert!(!check(AUTH_ROLE_NONE, 0), "a stranger is refused a Member replica");
        assert!(check(AUTH_ROLE_READONLY, 0), "a granted member is served");
        assert!(
            check(AUTH_ROLE_NONE, NODE_ROLE_REPLY_VOTER),
            "an enrolled voter is served before a grant lands",
        );
        // Anonymous (no peer id) is refused for a non-Public floor.
        let (routes, _reg) = spawn_stub_role_registry(AUTH_ROLE_READONLY, NODE_ROLE_REPLY_VOTER);
        let svc = lifecycle_service(
            routes,
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(std::sync::RwLock::new(HashMap::new())),
        );
        svc.sync_floor_cache
            .write()
            .unwrap()
            .insert("counter".to_string(), (SyncFloor::Member, Instant::now()));
        assert!(!svc.sync_serve_allowed(None, "counter"), "anonymous is refused Member");
    }

    #[cfg(feature = "network")]
    fn lifecycle_service(
        routes: InvokeRoutes,
        shutdown: AgentShutdown,
        info: AgentInfos,
    ) -> NodeService {
        NodeService {
            invoke_routes: routes,
            agent_names: Arc::new(std::sync::RwLock::new(HashMap::new())),
            agent_shutdown: shutdown,
            agent_info: info,
            #[cfg(feature = "storage")]
            replicas: Arc::new(Mutex::new(HashMap::new())),
            manifest: Arc::new(OnceLock::new()),
            proof_blobs: Arc::new(RwLock::new(HashMap::new())),
            proof_blobs_dir: None,
            operator_peer: None,
            #[cfg(feature = "storage")]
            sync_floor_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// The node-level `__stop` / `__describe`
    /// interceptor answers those reserved wire methods host-side — for an
    /// agent with **no invoke route** (a transport extension like the
    /// gateway) — when the caller is authorized (ADMIN for stop, member for
    /// describe). `__describe` returns the JSON snapshot; `__stop` flips the
    /// agent's shutdown flag and replies Unit.
    #[cfg(feature = "network")]
    #[test]
    fn lifecycle_interceptor_admin_stops_and_describes() {
        use crate::actors::codec::{Decode, Encode};
        use crate::network::NetworkService;
        use crate::value::{Msg, TAG_DYNAMIC, Value};

        let target = ServiceId::new(0x00ab, 0x0123);
        let flag = Arc::new(AtomicBool::new(false));
        let shutdown: AgentShutdown =
            Arc::new(Mutex::new(HashMap::from([(target.0, flag.clone())])));
        let info: AgentInfos = Arc::new(std::sync::RwLock::new(HashMap::from([(
            target.0,
            AgentInfo {
                name: Some("gateway".into()),
                kind: crate::extension::ExtensionKind::Transport as u8,
                serves_addr: Some("127.0.0.1:8080".into()),
                consistency: None,
                network_reachable: true,
            },
        )])));

        // Registry grants this peer ADMIN. NOTE: the target itself has NO
        // route — the interceptor must answer before the route lookup.
        let (routes, reg) = spawn_stub_peer_role_registry(AUTH_ROLE_ADMIN);
        let service = lifecycle_service(routes, shutdown, info);
        let peer = libp2p::PeerId::random();

        // __describe → rkyv Value::Str(json) with the live running flag.
        let mut payload = vec![TAG_DYNAMIC];
        payload.extend_from_slice(&Msg::new("__describe").encode());
        let reply = service.dispatch_invoke(Some(peer), 0, target.0, vec![], payload);
        let json = match <Value as Decode>::decode(&reply) {
            Value::Str(s) => s,
            other => panic!("__describe should reply Value::Str, got {other:?}"),
        };
        assert!(
            json.contains("\"name\":\"gateway\"")
                && json.contains("\"kind\":2")
                && json.contains("\"running\":true")
                && json.contains("127.0.0.1:8080"),
            "describe json: {json}",
        );

        // __stop → empty reply (Unit) + flag flipped.
        assert!(!flag.load(Ordering::Relaxed));
        let mut payload = vec![TAG_DYNAMIC];
        payload.extend_from_slice(&Msg::new("__stop").encode());
        let reply = service.dispatch_invoke(Some(peer), 0, target.0, vec![], payload);
        assert!(
            reply.is_empty(),
            "__stop replies empty (Value::Unit → null)"
        );
        assert!(
            flag.load(Ordering::Relaxed),
            "__stop must flip the agent's shutdown flag",
        );

        drop(service);
        reg.join().unwrap();
    }

    /// A non-admin / non-member caller is REFUSED —
    /// `__stop`/`__describe` return a `STATUS_FORBIDDEN` envelope and the
    /// agent's shutdown flag is NOT touched. Closes the "any dialable peer
    /// can stop/enumerate any agent" hole.
    #[cfg(feature = "network")]
    #[test]
    fn lifecycle_interceptor_refuses_non_member() {
        use crate::actors::codec::Encode;
        use crate::network::NetworkService;
        use crate::value::{Msg, TAG_DYNAMIC};

        let target = ServiceId::new(0x00ab, 0x0123);
        let flag = Arc::new(AtomicBool::new(false));
        let shutdown: AgentShutdown =
            Arc::new(Mutex::new(HashMap::from([(target.0, flag.clone())])));
        let info: AgentInfos = Arc::new(std::sync::RwLock::new(HashMap::from([(
            target.0,
            AgentInfo {
                name: Some("gateway".into()),
                kind: 2,
                serves_addr: Some("127.0.0.1:8080".into()),
                consistency: None,
                network_reachable: true,
            },
        )])));

        // Registry grants this peer NO role (non-member).
        let (routes, reg) = spawn_stub_peer_role_registry(AUTH_ROLE_NONE);
        let service = lifecycle_service(routes, shutdown, info);
        let peer = libp2p::PeerId::random();

        for method in ["__stop", "__describe"] {
            let mut payload = vec![TAG_DYNAMIC];
            payload.extend_from_slice(&Msg::new(method).encode());
            let reply = service.dispatch_invoke(Some(peer), 0, target.0, vec![], payload);
            assert_eq!(
                reply.first().copied(),
                Some(crate::actors::run::STATUS_FORBIDDEN),
                "{method} from a non-member must return a STATUS_FORBIDDEN envelope",
            );
        }
        assert!(
            !flag.load(Ordering::Relaxed),
            "a refused __stop must NOT flip the shutdown flag",
        );

        drop(service);
        reg.join().unwrap();
    }

    // ── R4: actor-local grant propagated through extension relays ──

    /// Spawn a mock registry on route 0 that replies `role` to every
    /// `actor_role` probe, recording each probe's `(agent_name,
    /// peer_id)`. Returns the routes table, the record, and the thread.
    #[cfg(feature = "network")]
    fn mock_registry_actor_role(
        role: u8,
    ) -> (
        InvokeRoutes,
        Arc<Mutex<Vec<(String, Vec<u8>)>>>,
        thread::JoinHandle<()>,
    ) {
        use crate::actors::codec::{Decode, Encode};
        use crate::actors::run::STATUS_DONE;
        use crate::value::{Msg, Value};
        let (reg_tx, reg_rx) = mpsc::channel::<InvokeRequest>();
        let seen: Arc<Mutex<Vec<(String, Vec<u8>)>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_w = seen.clone();
        let h = thread::spawn(move || {
            while let Ok(req) = reg_rx.recv() {
                let msg = <Msg as Decode>::try_decode(&req.msg[1..]).expect("decode probe");
                let peer = msg.args.get_bytes("peer_id").unwrap_or_default();
                let name = msg.args.get_str("agent_name").unwrap_or_default();
                seen_w.lock().unwrap().push((name, peer));
                let reply = encode_invoke_envelope(STATUS_DONE, &[], &Value::U8(role).encode());
                let _ = req.reply.send(reply);
            }
        });
        let mut routes = HashMap::new();
        routes.insert(ServiceId::REGISTRY.0, reg_tx);
        (Arc::new(Mutex::new(routes)), seen, h)
    }

    /// The headline R4 property: a peer's actor-local grant on the final
    /// target is relayed **faithfully and uncapped** when the cap merely
    /// *permits* the relay. Here the cap ceiling is Member but the grant
    /// is role 3 (the actor's own role space) — the returned role is 3,
    /// not min(3, Member): the host can't compare the two spaces, and
    /// the peer already holds the grant on a direct call.
    #[cfg(feature = "network")]
    #[test]
    fn relay_actor_local_propagates_peer_grant_uncapped_when_cap_permits() {
        use crate::actors::{Caller, IntraCap, SpaceRole};
        let (routes, seen, h) = mock_registry_actor_role(3);
        let caps = vec![IntraCap::parse("dev-project:member").unwrap()];
        let pc = PropagatedCaller {
            caller: Caller::Peer(vec![1, 2, 3]),
            space_role: Some(SpaceRole::Guest.as_u8()),
        };
        let got = relay_actor_local_role(&routes, Some(&pc), &caps, Some("dev-project"));
        assert_eq!(got, Some((vec![1, 2, 3], 3)));
        // The probe was keyed on the propagated peer + the target name.
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            &[("dev-project".to_string(), vec![1, 2, 3])]
        );
        drop(routes);
        h.join().unwrap();
    }

    /// No cap for the target → the relay isn't permitted at all, so the
    /// actor-local grant must NOT tunnel through (and no probe fires).
    #[cfg(feature = "network")]
    #[test]
    fn relay_actor_local_denied_without_a_permitting_cap() {
        use crate::actors::{Caller, SpaceRole};
        let (routes, seen, h) = mock_registry_actor_role(3);
        let pc = PropagatedCaller {
            caller: Caller::Peer(vec![1]),
            space_role: Some(SpaceRole::Admin.as_u8()),
        };
        assert_eq!(
            relay_actor_local_role(&routes, Some(&pc), &[], Some("dev-project")),
            None
        );
        assert!(seen.lock().unwrap().is_empty(), "no cap → no probe");
        drop(routes);
        h.join().unwrap();
    }

    /// Only Peer callers carry actor-local grants. A trusted incoming
    /// caller (System/Actor) is relayed anonymously and has no peer
    /// identity to key a grant on.
    #[cfg(feature = "network")]
    #[test]
    fn relay_actor_local_skips_non_peer_callers() {
        use crate::actors::{Caller, IntraCap};
        let (routes, seen, h) = mock_registry_actor_role(3);
        let caps = vec![IntraCap::parse("*:admin").unwrap()];
        let pc = PropagatedCaller {
            caller: Caller::System,
            space_role: None,
        };
        assert_eq!(
            relay_actor_local_role(&routes, Some(&pc), &caps, Some("dev-project")),
            None
        );
        assert!(seen.lock().unwrap().is_empty());
        drop(routes);
        h.join().unwrap();
    }

    /// `AUTH_ROLE_NONE` (no grant row) → `None`, mirroring the dispatch
    /// path; an unresolved target name → `None` (nothing to key on).
    #[cfg(feature = "network")]
    #[test]
    fn relay_actor_local_none_for_missing_grant_or_name() {
        use crate::actors::{Caller, IntraCap, SpaceRole};
        let caps = vec![IntraCap::parse("*:admin").unwrap()];
        let peer = || PropagatedCaller {
            caller: Caller::Peer(vec![9]),
            space_role: Some(SpaceRole::Member.as_u8()),
        };

        // Registry has no row for the peer (replies AUTH_ROLE_NONE).
        let (routes, _seen, h) = mock_registry_actor_role(AUTH_ROLE_NONE);
        assert_eq!(
            relay_actor_local_role(&routes, Some(&peer()), &caps, Some("dev-project")),
            None
        );
        drop(routes);
        h.join().unwrap();

        // Unresolved target name → no key, no probe.
        let (routes, seen, h) = mock_registry_actor_role(3);
        assert_eq!(
            relay_actor_local_role(&routes, Some(&peer()), &caps, None),
            None
        );
        assert!(seen.lock().unwrap().is_empty());
        drop(routes);
        h.join().unwrap();
    }

    /// A3 — commit-then-outbox: a dispatch that produces an external
    /// transfer must route it only after the commit succeeds. A failed
    /// commit routes nothing (no leak); a subsequent successful attempt
    /// routes exactly once (the failed attempt did not duplicate).
    #[test]
    fn dispatch_routes_external_transfers_only_after_commit() {
        use crate::actors::codec::Encode;
        use crate::value::{Msg, TAG_DYNAMIC};
        use std::sync::mpsc;

        let workspace = env!("CARGO_MANIFEST_DIR");
        let elf_path = format!(
            "{workspace}/../examples/actors/probe/target/riscv64em-javm/release/probe.elf"
        );
        let Ok(elf) = std::fs::read(&elf_path) else {
            eprintln!("SKIP: probe ELF not built — run: just build-pvm");
            return;
        };
        let blob = grey_transpiler::link_elf(&elf).expect("probe transpiles");

        let mut runtime = VosRuntime::new();
        let blob_idx = runtime.register_service_blob(blob);
        let probe = runtime.register_service(blob_idx);

        // A tell to a service this runtime does not host is an external
        // transfer routed through the node's outbox.
        let external_target = ServiceId(0xEE00);
        let tell = {
            let enc = Msg::new("tell_out").with("target", external_target.0).encode();
            let mut m = vec![TAG_DYNAMIC];
            m.extend_from_slice(&enc);
            m
        };

        let (tx, rx) = mpsc::channel::<Envelope>();

        struct FailCommit;
        impl crate::commit::CommitStrategy for FailCommit {
            fn restore(&mut self) -> Option<Vec<u8>> {
                None
            }
            fn commit(
                &mut self,
                _delta: &crate::commit::AgentDelta<'_>,
            ) -> Result<crate::commit::CommitReceipt, crate::commit::CommitError> {
                Err(crate::commit::CommitError::Config(
                    "forced commit failure".into(),
                ))
            }
        }

        // First attempt: the commit fails, so nothing may be routed.
        let mut fail = FailCommit;
        let r = dispatch_once(&mut runtime, probe, &tx, probe, Some(tell.clone()), &mut fail, false);
        assert!(r.is_err(), "the failing strategy must surface its commit error");
        assert!(
            rx.try_recv().is_err(),
            "a failed commit must route no external transfer"
        );

        // Retry with a strategy that commits: the transfer routes once.
        let mut ok = crate::commit::NoCommit;
        let r = dispatch_once(&mut runtime, probe, &tx, probe, Some(tell), &mut ok, false);
        assert!(r.is_ok(), "the succeeding strategy must commit");
        let env = rx
            .try_recv()
            .expect("a committed dispatch routes its external transfer");
        assert_eq!(env.to, external_target);
        assert!(
            rx.try_recv().is_err(),
            "exactly one transfer routed — the failed attempt left nothing to duplicate"
        );
    }
}
