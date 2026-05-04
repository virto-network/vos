//! Networking layer — peer transport over libp2p.
//!
//! [`Network`] runs the libp2p swarm on its own tokio thread,
//! independent of [`VosNode`](crate::node::VosNode). Cycle 1 stood
//! up the pipe (TCP/Noise/yamux/mDNS/identify/ping); cycle 2 added
//! the wire format and a `request_response` channel for cross-node
//! envelopes.
//!
//! # What's wired up today
//!
//! - TCP / Noise / yamux transport.
//! - Identify + ping for keepalive and peer info exchange.
//! - mDNS for LAN peer discovery.
//! - `Identity::auto` derives (or loads) an Ed25519 keypair at
//!   `{data_dir}/node.key`; explicit `path` strings load the
//!   keypair from that file.
//! - `request_response` over `/vos/0.1.0` carrying [`Frame`]:
//!   `Hello` exchanges `node_prefix` on first contact, `Tell`
//!   delivers fire-and-forget envelopes. Inbound Tell is pushed
//!   into the caller-supplied [`NetworkConfig::inbox`].
//!
//! # Out of scope (later cycles)
//!
//! - InvokeRequest / InvokeReply frames cross-node (cycle 2.5).
//! - VosNode integration so `route()` forwards non-local prefixes
//!   over the network.
//! - CRDT gossip / sync via libp2p pubsub.
//! - Hyperspace-driven peer discovery.

#![cfg(feature = "network")]

mod codec;
mod wire;

pub use wire::{
    Frame, FrameError, ManifestBlob, RaftEntry, RaftEntryKind, RaftJoinResult,
    MAX_FRAME_BYTES,
};

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{mpsc as std_mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use libp2p::futures::StreamExt;
use libp2p::gossipsub;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identify, identity, mdns, noise, ping, tcp, yamux, Multiaddr, PeerId, Swarm};
use tokio::sync::mpsc as async_mpsc;
use tracing::{debug, error, info, warn};

use codec::{VosCodec, PROTOCOL};

/// Combined libp2p behaviour.
#[derive(NetworkBehaviour)]
struct VosBehaviour {
    mdns: mdns::tokio::Behaviour,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    req_resp: request_response::Behaviour<VosCodec>,
    /// Push-based head announcements per replication group.
    /// Each replica subscribes to `vos/sync/{rep_id_hex}` and
    /// publishes the encoded `Frame::Heads` after every commit.
    /// Subscribers schedule an immediate
    /// [`sync_with_peer`](crate::node::sync_with_peer)-style
    /// fetch against the publisher rather than waiting for the
    /// next 250ms tick.
    gossip: gossipsub::Behaviour,
}

/// One-way envelope received from a remote peer. Pushed to the
/// channel handed back by [`Network::take_inbox`].
#[derive(Debug, Clone)]
pub struct InboundTell {
    pub from: u32,
    pub to: u32,
    pub payload: Vec<u8>,
}

/// Handler invoked by the network thread when a remote peer sends
/// us a `Frame::InvokeRequest`. The implementation typically
/// dispatches against the local invoke-route table and blocks on
/// the agent's reply (the network calls `dispatch` from a
/// `tokio::task::spawn_blocking`, so blocking is safe). Returning
/// an empty `Vec` is interpreted as "no reply" / "target not
/// found" and surfaces to the original caller as an empty
/// `InvokeReply`.
pub trait InvokeDispatcher: Send + Sync {
    fn dispatch(&self, from: u32, to: u32, chain: Vec<u32>, msg: Vec<u8>) -> Vec<u8>;
}

/// Read-side of CRDT replication: looks up DAG state for a given
/// replication group. The network thread calls these methods
/// directly on its current_thread tokio runtime; implementations
/// must return quickly (a redb read transaction is fine — micro-
/// seconds typically, well below the cross-await budget).
pub trait SyncProvider: Send + Sync {
    /// Return the current root CIDs for a replication group, or
    /// `None` if no replica of that group is registered locally.
    fn roots(&self, replication_id: &[u8; 32]) -> Option<Vec<[u8; 32]>>;

    /// Look up a single DAG node's serialized bytes inside a
    /// replication group. `None` means the local replica doesn't
    /// have the node yet (sync racing) or the group is unknown.
    fn get_node(&self, replication_id: &[u8; 32], cid: &[u8; 32]) -> Option<Vec<u8>>;
}

/// Inbound result from an [`AppendEntries`](Frame::RaftAppendReq)
/// RPC, returned by [`RaftRpcHandler::append_entries`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaftAppendResult {
    pub term: u64,
    pub success: bool,
    pub match_index: u64,
}

/// Inbound result from a [`RequestVote`](Frame::RaftVoteReq) RPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaftVoteResult {
    pub term: u64,
    pub vote_granted: bool,
}

/// Inbound result from an
/// [`InstallSnapshot`](Frame::RaftInstallSnapshotReq) RPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaftInstallSnapshotResult {
    pub term: u64,
}

/// Reply to a [`RaftStatusReq`](Frame::RaftStatusReq) — a peer's
/// view of one Raft replication group. Mirrors
/// `vos_raft::WorkerSnapshot` minus the storage cursor that
/// only matters internally. `present = false` means the peer
/// isn't running the requested group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaftStatusReply {
    pub present: bool,
    pub role: RaftRole,
    pub current_term: u64,
    pub commit_index: u64,
    pub last_log_index: u64,
    pub members: Vec<u16>,
    pub leader_hint: Option<u16>,
}

/// Wire-stable Raft role. Distinct from `vos_raft::Role` so we
/// can grow the consensus core (e.g. add a learner / observer
/// variant) without flipping the wire encoding. `Unknown(u8)`
/// catches future variants reported by a newer peer — the
/// current operator can still parse the rest of the reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaftRole {
    Follower,
    PreCandidate,
    Candidate,
    Leader,
    /// Future variant a newer peer used. Operators see this as
    /// `?` in `vosx ps`; the bootnode and joiner code treat it
    /// the same as Follower for routing purposes.
    Unknown(u8),
}

impl RaftRole {
    /// Encode to the on-wire byte. Layout chosen to match
    /// `vos_raft::Role as u8` for the four real variants so a
    /// receiver decoding straight from a `WorkerSnapshot`
    /// produces the same bytes as one going through this enum.
    pub fn to_wire(self) -> u8 {
        match self {
            Self::Follower => 0,
            Self::PreCandidate => 1,
            Self::Candidate => 2,
            Self::Leader => 3,
            Self::Unknown(b) => b,
        }
    }

    /// Decode from the on-wire byte. Unknown values become
    /// `RaftRole::Unknown(b)` rather than failing — forward-
    /// compatible with newer peers reporting future roles.
    pub fn from_wire(b: u8) -> Self {
        match b {
            0 => Self::Follower,
            1 => Self::PreCandidate,
            2 => Self::Candidate,
            3 => Self::Leader,
            other => Self::Unknown(other),
        }
    }

    /// Human-readable label for `vosx ps`-style output.
    pub fn label(self) -> &'static str {
        match self {
            Self::Follower => "Follower",
            Self::PreCandidate => "PreCand.",
            Self::Candidate => "Candidate",
            Self::Leader => "Leader",
            Self::Unknown(_) => "?",
        }
    }
}

impl RaftStatusReply {
    /// Construct a "no, I don't host this group" reply.
    pub fn absent() -> Self {
        Self {
            present: false,
            role: RaftRole::Follower,
            current_term: 0,
            commit_index: 0,
            last_log_index: 0,
            members: Vec::new(),
            leader_hint: None,
        }
    }
}

/// Local provider for the bootnode's manifest. Implemented by
/// `vosx` so a fresh `vosx join <bootnode>` can fetch the
/// space.toml + actor blobs without the operator pre-distributing
/// the manifest. Returns `None` for nodes that don't expose a
/// manifest (transient peers, manifest-less raw `vosx run`).
pub trait ManifestProvider: Send + Sync {
    /// `(toml_bytes, blobs)` — the raw `space.toml` content and a
    /// list of every actor blob the manifest references, keyed
    /// by name. The joiner writes the blobs into a local cache
    /// keyed by the same name so its replication_id derivation
    /// (`blake2b(name || 0 || blob)`) lines up with the bootnode's.
    fn manifest(&self) -> Option<(Vec<u8>, Vec<ManifestBlob>)>;
}

/// Local handler for inbound Raft RPCs. Mirrors [`SyncProvider`]'s
/// shape: the swarm thread invokes the trait methods on its current-
/// thread runtime, so implementations must be fast. Any redb writes
/// implied by an `append_entries` call should be funnelled through
/// the handler's own background task; the trait returns synchronously
/// only the *response* the peer sees.
pub trait RaftRpcHandler: Send + Sync {
    /// Inbound `AppendEntries` from `from_prefix`. Returns the
    /// response the peer will read. Implementations are responsible
    /// for log consistency checks, term updates, applying entries,
    /// and any local persistence — the network layer just delivers
    /// the call and ferries the answer back.
    fn append_entries(
        &self,
        replication_id: &[u8; 32],
        from_prefix: u16,
        term: u64,
        prev_log_index: u64,
        prev_log_term: u64,
        leader_commit: u64,
        entries: Vec<RaftEntry>,
    ) -> RaftAppendResult;

    /// Inbound `RequestVote` from `from_prefix`. Returns the
    /// response. Implementations are responsible for the
    /// up-to-date check and the at-most-one-vote-per-term rule.
    fn request_vote(
        &self,
        replication_id: &[u8; 32],
        from_prefix: u16,
        term: u64,
        last_log_index: u64,
        last_log_term: u64,
    ) -> RaftVoteResult;

    /// Inbound `InstallSnapshot` from `from_prefix` (the leader).
    /// Implementations replace the local actor state, advance
    /// the snap pointer, and drop any log entries the snapshot
    /// supersedes — atomically, before answering. The default
    /// impl just refuses (advertises our current term) so older
    /// handlers stay safely on the AppendEntries path.
    fn install_snapshot(
        &self,
        _replication_id: &[u8; 32],
        _from_prefix: u16,
        term: u64,
        _last_included_index: u64,
        _last_included_term: u64,
        _snapshot: Vec<u8>,
    ) -> RaftInstallSnapshotResult {
        RaftInstallSnapshotResult { term }
    }

    /// Inbound `RaftJoinReq` from a fresh node that wants to
    /// become a voter in this replication group. Default impl
    /// returns `NotLeader { leader_hint: None }` — handlers
    /// representing real workers override this to: (a) check
    /// they're the leader, (b) compute `new_members = current ∪
    /// {joiner}`, and (c) call `change_membership(...)`. On
    /// success, return `Accepted { joint_index }` so the joiner
    /// can poll for `commit_index >= joint_index + 1`.
    fn handle_join(
        &self,
        _replication_id: &[u8; 32],
        _joiner_prefix: u16,
    ) -> RaftJoinResult {
        RaftJoinResult::NotLeader { leader_hint: None }
    }

    /// Inbound `RaftStatusReq` — answer "what's your view of
    /// replication group X?" from a vosx-ps observer. Default
    /// impl returns [`RaftStatusReply::absent`]; concrete
    /// handlers override to translate their `WorkerSnapshot`.
    fn handle_status(&self, _replication_id: &[u8; 32]) -> RaftStatusReply {
        RaftStatusReply::absent()
    }
}

/// Map: peer's `node_prefix` → its `PeerId`. Populated as Hello
/// frames flow in. Cheap to clone — owned by both the swarm
/// thread and any [`Network`] callers that want to look up a
/// peer by prefix.
type PrefixMap = Arc<Mutex<HashMap<u16, PeerId>>>;

/// Map: replication-group id → handler. Each Raft group running
/// on this node registers itself via
/// [`Network::register_raft_handler`]; the swarm thread routes
/// inbound Raft RPCs to the handler whose `replication_id`
/// matches the frame's. Pre-multi-group code stored a single
/// `Option<Arc<...>>`; multi-group dispatch (one Raft cluster per
/// `[[agent]] consistency = "raft"`) needs the map.
type RaftHandlerMap = Arc<Mutex<BTreeMap<[u8; 32], Arc<dyn RaftRpcHandler>>>>;

/// Multiaddrs the local swarm has actually bound to. Populated
/// from `SwarmEvent::NewListenAddr`. Useful for tests that bind
/// to port 0 and need the kernel-assigned port.
type ListenAddrs = Arc<Mutex<Vec<Multiaddr>>>;

/// Handle to the running network thread. Drop or call
/// [`shutdown`](Self::shutdown) to wind it down.
pub struct Network {
    peer_id: PeerId,
    local_prefix: u16,
    cmd_tx: async_mpsc::UnboundedSender<NetworkCmd>,
    prefix_map: PrefixMap,
    listen_addrs: ListenAddrs,
    inbox_rx: Mutex<Option<std_mpsc::Receiver<InboundTell>>>,
    /// Set via [`set_invoke_dispatcher`](Self::set_invoke_dispatcher).
    /// Read by the swarm thread on every inbound `InvokeRequest`
    /// to dispatch against the local node.
    invoke_dispatcher: Arc<Mutex<Option<Arc<dyn InvokeDispatcher>>>>,
    /// Set via [`set_sync_provider`](Self::set_sync_provider).
    /// Read by the swarm thread on every inbound `FetchHeads` /
    /// `FetchNode` to look up the local replica.
    sync_provider: Arc<Mutex<Option<Arc<dyn SyncProvider>>>>,
    /// Per-replication-group inbound Raft handler map. Populated
    /// via [`register_raft_handler`](Self::register_raft_handler);
    /// read by the swarm thread on every inbound
    /// `RaftAppendReq` / `RaftVoteReq` / `RaftInstallSnapshotReq`
    /// to route the call to the right group's state machine.
    /// Frames carrying a `replication_id` with no entry surface to
    /// the peer as the default empty / current-term answer.
    raft_handlers: RaftHandlerMap,
    /// Set via [`set_manifest_provider`](Self::set_manifest_provider).
    /// Read by the swarm thread on inbound `ManifestReq` frames
    /// so a fresh `vosx join` can fetch the bootnode's space.toml
    /// + actor blobs.
    manifest_provider: Arc<Mutex<Option<Arc<dyn ManifestProvider>>>>,
    join: Option<JoinHandle<()>>,
}

/// Configuration for the libp2p layer.
pub struct NetworkConfig {
    /// libp2p keypair. Use [`load_or_generate_identity`] to derive
    /// one from the manifest's `[node].identity` field.
    pub keypair: identity::Keypair,
    /// 16-bit identifier this node uses in the high bits of every
    /// `ServiceId` it allocates. Exchanged with peers on first
    /// contact via [`Frame::Hello`] so they can resolve target
    /// prefixes back to a `PeerId`.
    pub local_prefix: u16,
    /// Multiaddrs the node listens on. Empty = no inbound
    /// connections (the node is dial-only).
    pub listen: Vec<Multiaddr>,
    /// Multiaddrs to dial at startup. Useful when not relying on
    /// mDNS / hyperspace discovery.
    pub bootstrap: Vec<Multiaddr>,
}

enum NetworkCmd {
    Connect(Multiaddr),
    SendTell {
        target_peer: PeerId,
        from: u32,
        to: u32,
        payload: Vec<u8>,
    },
    SendInvoke {
        target_peer: PeerId,
        from: u32,
        to: u32,
        chain: Vec<u32>,
        msg: Vec<u8>,
        reply: std_mpsc::Sender<Vec<u8>>,
    },
    SendFetchHeads {
        target_peer: PeerId,
        replication_id: [u8; 32],
        reply: std_mpsc::Sender<Vec<[u8; 32]>>,
    },
    SendFetchNode {
        target_peer: PeerId,
        replication_id: [u8; 32],
        cid: [u8; 32],
        reply: std_mpsc::Sender<Option<Vec<u8>>>,
    },
    /// Subscribe the local node to the gossipsub topic for a
    /// replication group. Idempotent — re-subscribing is a no-op.
    SubscribeRep { replication_id: [u8; 32] },
    /// Publish a head announcement for a replication group on
    /// its gossipsub topic. Subscribers schedule an immediate
    /// fetch from the publisher rather than waiting for the
    /// next sync tick.
    PublishHeads {
        replication_id: [u8; 32],
        roots: Vec<[u8; 32]>,
    },
    /// Register a sender that the swarm thread pushes hint
    /// `(peer)` pairs into when it receives a head announcement
    /// for this replication group. The matching sync_loop drains
    /// the receiver and triggers an immediate fetch.
    RegisterHintSender {
        replication_id: [u8; 32],
        sender: std_mpsc::Sender<PeerId>,
    },
    /// Send a Raft `AppendEntries` RPC to a specific peer. Reply
    /// channel yields `RaftAppendResult` on success; dropped on
    /// transport failure (caller's recv yields `Disconnected`).
    SendRaftAppend {
        target_peer: PeerId,
        replication_id: [u8; 32],
        term: u64,
        leader_prefix: u16,
        prev_log_index: u64,
        prev_log_term: u64,
        leader_commit: u64,
        entries: Vec<RaftEntry>,
        reply: std_mpsc::Sender<RaftAppendResult>,
    },
    /// Send a Raft `RequestVote` RPC to a specific peer.
    SendRaftVote {
        target_peer: PeerId,
        replication_id: [u8; 32],
        term: u64,
        candidate_prefix: u16,
        last_log_index: u64,
        last_log_term: u64,
        reply: std_mpsc::Sender<RaftVoteResult>,
    },
    /// Send a Raft `InstallSnapshot` RPC to a specific peer.
    SendRaftInstallSnapshot {
        target_peer: PeerId,
        replication_id: [u8; 32],
        term: u64,
        leader_prefix: u16,
        last_included_index: u64,
        last_included_term: u64,
        snapshot: Vec<u8>,
        reply: std_mpsc::Sender<RaftInstallSnapshotResult>,
    },
    /// Send a [`Frame::RaftJoinReq`] to a peer to add the local
    /// replica as a voter in their replication group. Reply
    /// yields the join outcome.
    SendRaftJoin {
        target_peer: PeerId,
        replication_id: [u8; 32],
        joiner_prefix: u16,
        reply: std_mpsc::Sender<RaftJoinResult>,
    },
    /// Send a [`Frame::ManifestReq`] to a bootnode. Reply yields
    /// the bootnode's space.toml + actor blobs.
    SendManifestReq {
        target_peer: PeerId,
        reply: std_mpsc::Sender<(Vec<u8>, Vec<ManifestBlob>)>,
    },
    /// Send a [`Frame::RaftStatusReq`] for one replication
    /// group. Reply yields the peer's view of the group.
    SendRaftStatus {
        target_peer: PeerId,
        replication_id: [u8; 32],
        reply: std_mpsc::Sender<RaftStatusReply>,
    },
    Shutdown,
}

/// Outbound request kinds tracked while we wait for the reply.
enum OutboundReply {
    Invoke(std_mpsc::Sender<Vec<u8>>),
    Heads(std_mpsc::Sender<Vec<[u8; 32]>>),
    Node(std_mpsc::Sender<Option<Vec<u8>>>),
    RaftAppend(std_mpsc::Sender<RaftAppendResult>),
    RaftVote(std_mpsc::Sender<RaftVoteResult>),
    RaftInstallSnapshot(std_mpsc::Sender<RaftInstallSnapshotResult>),
    RaftJoin(std_mpsc::Sender<RaftJoinResult>),
    Manifest(std_mpsc::Sender<(Vec<u8>, Vec<ManifestBlob>)>),
    RaftStatus(std_mpsc::Sender<RaftStatusReply>),
}

impl Network {
    /// Spin up the libp2p swarm on a dedicated thread.
    pub fn start(config: NetworkConfig) -> Self {
        let peer_id = PeerId::from(config.keypair.public());
        let local_prefix = config.local_prefix;
        let prefix_map: PrefixMap = Arc::new(Mutex::new(HashMap::new()));
        let listen_addrs: ListenAddrs = Arc::new(Mutex::new(Vec::new()));
        let invoke_dispatcher: Arc<Mutex<Option<Arc<dyn InvokeDispatcher>>>> =
            Arc::new(Mutex::new(None));
        let sync_provider: Arc<Mutex<Option<Arc<dyn SyncProvider>>>> =
            Arc::new(Mutex::new(None));
        let raft_handlers: RaftHandlerMap = Arc::new(Mutex::new(BTreeMap::new()));
        let manifest_provider: Arc<Mutex<Option<Arc<dyn ManifestProvider>>>> =
            Arc::new(Mutex::new(None));
        let (cmd_tx, cmd_rx) = async_mpsc::unbounded_channel();
        let (inbox_tx, inbox_rx) = std_mpsc::channel();

        let prefix_map_for_thread = prefix_map.clone();
        let listen_addrs_for_thread = listen_addrs.clone();
        let invoke_dispatcher_for_thread = invoke_dispatcher.clone();
        let sync_provider_for_thread = sync_provider.clone();
        let raft_handlers_for_thread = raft_handlers.clone();
        let manifest_provider_for_thread = manifest_provider.clone();
        let join = thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    error!(error = %e, "network: failed to build tokio runtime");
                    return;
                }
            };
            rt.block_on(network_main(
                config,
                cmd_rx,
                prefix_map_for_thread,
                listen_addrs_for_thread,
                inbox_tx,
                invoke_dispatcher_for_thread,
                sync_provider_for_thread,
                raft_handlers_for_thread,
                manifest_provider_for_thread,
            ));
        });

        Self {
            peer_id,
            local_prefix,
            cmd_tx,
            prefix_map,
            listen_addrs,
            inbox_rx: Mutex::new(Some(inbox_rx)),
            invoke_dispatcher,
            sync_provider,
            raft_handlers,
            manifest_provider,
            join: Some(join),
        }
    }

    /// Install the handler used to dispatch inbound `InvokeRequest`
    /// frames into the local node. Without it, remote invokes
    /// receive an empty `InvokeReply`.
    pub fn set_invoke_dispatcher(&self, dispatcher: Arc<dyn InvokeDispatcher>) {
        if let Ok(mut g) = self.invoke_dispatcher.lock() {
            *g = Some(dispatcher);
        }
    }

    /// Install the handler used to answer inbound `FetchHeads` /
    /// `FetchNode` frames against the local CRDT replicas.
    /// Without it, peers asking us for sync data get empty
    /// replies.
    pub fn set_sync_provider(&self, provider: Arc<dyn SyncProvider>) {
        if let Ok(mut g) = self.sync_provider.lock() {
            *g = Some(provider);
        }
    }

    /// Register a handler for one Raft replication group.
    /// Multiple groups can coexist on a single node — one
    /// `[[agent]] consistency = "raft"` per group — and the swarm
    /// thread routes inbound `RaftAppendReq` / `RaftVoteReq` /
    /// `RaftInstallSnapshotReq` to the handler whose
    /// `replication_id` matches the frame's. Inserting the same
    /// `replication_id` twice replaces the existing handler.
    pub fn register_raft_handler(
        &self,
        replication_id: [u8; 32],
        handler: Arc<dyn RaftRpcHandler>,
    ) {
        if let Ok(mut g) = self.raft_handlers.lock() {
            g.insert(replication_id, handler);
        }
    }

    /// Drop the handler for `replication_id`. Inbound RPCs for
    /// that group will surface to the peer as the
    /// no-handler default (current-term answer with `success =
    /// false`). Used when a replica leaves the cluster, or in
    /// tests that want to simulate a partition.
    pub fn unregister_raft_handler(&self, replication_id: &[u8; 32]) {
        if let Ok(mut g) = self.raft_handlers.lock() {
            g.remove(replication_id);
        }
    }

    /// Snapshot of every replication group with a registered
    /// handler. Returned in deterministic order (BTreeMap
    /// iteration). Used by the manifest-fetch / join paths to
    /// answer "what Raft groups is this node hosting?".
    pub fn registered_raft_groups(&self) -> Vec<[u8; 32]> {
        self.raft_handlers
            .lock()
            .map(|g| g.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Install the provider used to answer inbound `ManifestReq`
    /// frames so a fresh `vosx join` can fetch the bootnode's
    /// space.toml + actor blobs. Without it, peers asking us
    /// for the manifest get an empty reply.
    pub fn set_manifest_provider(&self, provider: Arc<dyn ManifestProvider>) {
        if let Ok(mut g) = self.manifest_provider.lock() {
            *g = Some(provider);
        }
    }

    /// Send a [`Frame::RaftJoinReq`] to a bootnode. The receiver
    /// either calls `change_membership` (returning
    /// [`RaftJoinResult::Accepted`]) or redirects with
    /// [`RaftJoinResult::NotLeader`] + a leader hint. The reply
    /// channel yields exactly once; on transport failure the
    /// Sender is dropped (`recv` yields `Disconnected`).
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

    /// Send a [`Frame::ManifestReq`] to a bootnode. The reply is
    /// `(toml_bytes, blobs)`; on transport failure the Sender is
    /// dropped. Used by `vosx join` when the operator hasn't
    /// supplied `--manifest`.
    pub fn send_manifest_req(
        &self,
        target_peer: PeerId,
    ) -> std_mpsc::Receiver<(Vec<u8>, Vec<ManifestBlob>)> {
        let (tx, rx) = std_mpsc::channel();
        let _ = self.cmd_tx.send(NetworkCmd::SendManifestReq {
            target_peer,
            reply: tx,
        });
        rx
    }

    /// Send a [`Frame::RaftStatusReq`] for one replication
    /// group. The reply describes that peer's view of the
    /// group. `vosx ps` fans this out across every connected
    /// peer to assemble the cluster snapshot.
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

    /// Send a Raft `AppendEntries` RPC to a specific peer. Receiver
    /// yields `RaftAppendResult`; on transport failure the Sender
    /// is dropped.
    #[allow(clippy::too_many_arguments)]
    pub fn send_raft_append(
        &self,
        target_peer: PeerId,
        replication_id: [u8; 32],
        term: u64,
        leader_prefix: u16,
        prev_log_index: u64,
        prev_log_term: u64,
        leader_commit: u64,
        entries: Vec<RaftEntry>,
    ) -> std_mpsc::Receiver<RaftAppendResult> {
        let (tx, rx) = std_mpsc::channel();
        let _ = self.cmd_tx.send(NetworkCmd::SendRaftAppend {
            target_peer,
            replication_id,
            term,
            leader_prefix,
            prev_log_index,
            prev_log_term,
            leader_commit,
            entries,
            reply: tx,
        });
        rx
    }

    /// Send a Raft `RequestVote` RPC to a specific peer.
    pub fn send_raft_vote(
        &self,
        target_peer: PeerId,
        replication_id: [u8; 32],
        term: u64,
        candidate_prefix: u16,
        last_log_index: u64,
        last_log_term: u64,
    ) -> std_mpsc::Receiver<RaftVoteResult> {
        let (tx, rx) = std_mpsc::channel();
        let _ = self.cmd_tx.send(NetworkCmd::SendRaftVote {
            target_peer,
            replication_id,
            term,
            candidate_prefix,
            last_log_index,
            last_log_term,
            reply: tx,
        });
        rx
    }

    /// Send a Raft `InstallSnapshot` RPC to a specific peer.
    #[allow(clippy::too_many_arguments)]
    pub fn send_raft_install_snapshot(
        &self,
        target_peer: PeerId,
        replication_id: [u8; 32],
        term: u64,
        leader_prefix: u16,
        last_included_index: u64,
        last_included_term: u64,
        snapshot: Vec<u8>,
    ) -> std_mpsc::Receiver<RaftInstallSnapshotResult> {
        let (tx, rx) = std_mpsc::channel();
        let _ = self.cmd_tx.send(NetworkCmd::SendRaftInstallSnapshot {
            target_peer,
            replication_id,
            term,
            leader_prefix,
            last_included_index,
            last_included_term,
            snapshot,
            reply: tx,
        });
        rx
    }

    /// Ask a peer for the current root CIDs of a replication
    /// group. The receiver yields the peer's roots vec; on
    /// failure the Sender is dropped (caller's recv yields
    /// `Disconnected`).
    pub fn fetch_heads(
        &self,
        target_peer: PeerId,
        replication_id: [u8; 32],
    ) -> std_mpsc::Receiver<Vec<[u8; 32]>> {
        let (tx, rx) = std_mpsc::channel();
        let _ = self.cmd_tx.send(NetworkCmd::SendFetchHeads {
            target_peer,
            replication_id,
            reply: tx,
        });
        rx
    }

    /// Point-fetch a single DAG node from a peer. The receiver
    /// yields `Some(bytes)` if the peer has the node, `None` if
    /// it doesn't (typical during sync racing).
    pub fn fetch_node(
        &self,
        target_peer: PeerId,
        replication_id: [u8; 32],
        cid: [u8; 32],
    ) -> std_mpsc::Receiver<Option<Vec<u8>>> {
        let (tx, rx) = std_mpsc::channel();
        let _ = self.cmd_tx.send(NetworkCmd::SendFetchNode {
            target_peer,
            replication_id,
            cid,
            reply: tx,
        });
        rx
    }

    /// Subscribe the local node to a replication group's
    /// gossipsub topic. Idempotent — call once per local
    /// replica when registered.
    pub fn subscribe_rep(&self, replication_id: [u8; 32]) {
        let _ = self.cmd_tx.send(NetworkCmd::SubscribeRep { replication_id });
    }

    /// Publish a head announcement for a replication group.
    /// Called by the agent thread after every commit so peers
    /// can pull the new state without waiting for the next 250ms
    /// sync tick.
    pub fn publish_heads(&self, replication_id: [u8; 32], roots: Vec<[u8; 32]>) {
        let _ = self.cmd_tx.send(NetworkCmd::PublishHeads { replication_id, roots });
    }

    /// Register a sender that receives hint `(peer)` whenever a
    /// gossipsub head announcement arrives for this replication
    /// group. The matching sync_loop drains the receiver and
    /// triggers an immediate fetch — that's how cycle 8 turns
    /// the previously-poll-only sync into a near-zero-latency
    /// push.
    pub fn register_hint_sender(
        &self,
        replication_id: [u8; 32],
        sender: std_mpsc::Sender<PeerId>,
    ) {
        let _ = self.cmd_tx.send(NetworkCmd::RegisterHintSender {
            replication_id,
            sender,
        });
    }

    /// Synchronously invoke a service on a remote peer. Returns a
    /// receiver that yields the reply bytes (rkyv-encoded `Value`)
    /// or, on failure, disconnects without sending — surfacing as
    /// `InvokeError::NotFound` at the caller.
    ///
    /// `chain` carries the synchronous-invoke stack of caller IDs
    /// for cycle / depth detection on the remote side; pass an
    /// empty vec if calling from outside the agent system.
    pub fn send_invoke(
        &self,
        target_peer: PeerId,
        from: u32,
        to: u32,
        chain: Vec<u32>,
        msg: Vec<u8>,
    ) -> std_mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = std_mpsc::channel();
        let _ = self.cmd_tx.send(NetworkCmd::SendInvoke {
            target_peer,
            from,
            to,
            chain,
            msg,
            reply: tx,
        });
        rx
    }

    /// Take ownership of the inbound-Tell receiver. The first call
    /// returns `Some(rx)`; subsequent calls return `None`. The
    /// caller is responsible for draining and dispatching frames
    /// — typically into a [`VosNode`](crate::node::VosNode)'s
    /// outbox via the bridge thread it sets up.
    pub fn take_inbox(&self) -> Option<std_mpsc::Receiver<InboundTell>> {
        self.inbox_rx.lock().ok()?.take()
    }

    /// Snapshot of multiaddrs the swarm has bound to. Empty until
    /// at least one listen has succeeded — callers that bind to
    /// port 0 typically poll this until non-empty.
    pub fn listen_addrs(&self) -> Vec<Multiaddr> {
        self.listen_addrs
            .lock()
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    /// The local libp2p peer ID.
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// The local 16-bit `node_prefix`. Same value passed in via
    /// [`NetworkConfig::local_prefix`].
    pub fn local_prefix(&self) -> u16 {
        self.local_prefix
    }

    /// Look up which peer owns a given `node_prefix`. Returns
    /// `None` until the peer has completed the Hello handshake.
    pub fn peer_for_prefix(&self, prefix: u16) -> Option<PeerId> {
        self.prefix_map.lock().ok()?.get(&prefix).copied()
    }

    /// Snapshot of every peer + its `node_prefix`, in no
    /// particular order. Same population as
    /// [`connected_peers`](Self::connected_peers); useful for
    /// operator UIs (`vosx status`) that want both halves
    /// without rebuilding the map peer-by-peer.
    pub fn peers_with_prefixes(&self) -> Vec<(u16, PeerId)> {
        self.prefix_map
            .lock()
            .map(|g| g.iter().map(|(p, id)| (*p, *id)).collect())
            .unwrap_or_default()
    }

    /// Snapshot of all peers that have completed the Hello
    /// handshake. Used by the sync ticker to fan out fetches
    /// across every reachable replica, since cycle 3 doesn't
    /// yet maintain a per-replication-group peer index.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.prefix_map
            .lock()
            .map(|g| g.values().copied().collect())
            .unwrap_or_default()
    }

    /// Dial a peer at the given multiaddr.
    pub fn connect(&self, addr: Multiaddr) {
        let _ = self.cmd_tx.send(NetworkCmd::Connect(addr));
    }

    /// Send a fire-and-forget envelope to a peer. The `target_peer`
    /// is typically obtained from [`peer_for_prefix`](Self::peer_for_prefix)
    /// using the `node_prefix` of the destination `ServiceId`.
    pub fn send_tell(&self, target_peer: PeerId, from: u32, to: u32, payload: Vec<u8>) {
        let _ = self.cmd_tx.send(NetworkCmd::SendTell {
            target_peer,
            from,
            to,
            payload,
        });
    }

    /// Signal the network thread to stop. The actual exit happens
    /// on the next swarm-event tick (≤ 50 ms typical).
    pub fn shutdown(&self) {
        let _ = self.cmd_tx.send(NetworkCmd::Shutdown);
    }

    /// Wait for the network thread to exit.
    pub fn join(mut self) {
        self.shutdown();
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        // Best-effort shutdown if the user didn't call .join().
        let _ = self.cmd_tx.send(NetworkCmd::Shutdown);
    }
}

async fn network_main(
    config: NetworkConfig,
    mut cmd_rx: async_mpsc::UnboundedReceiver<NetworkCmd>,
    prefix_map: PrefixMap,
    listen_addrs: ListenAddrs,
    inbox_tx: std_mpsc::Sender<InboundTell>,
    invoke_dispatcher: Arc<Mutex<Option<Arc<dyn InvokeDispatcher>>>>,
    sync_provider: Arc<Mutex<Option<Arc<dyn SyncProvider>>>>,
    raft_handlers: RaftHandlerMap,
    manifest_provider: Arc<Mutex<Option<Arc<dyn ManifestProvider>>>>,
) {
    let local_peer_id = PeerId::from(config.keypair.public());
    let local_prefix = config.local_prefix;
    info!(peer_id = %local_peer_id, prefix = format!("{local_prefix:#06x}"), "network: starting");

    let mut swarm = match build_swarm(config.keypair.clone()) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "network: failed to build swarm");
            return;
        }
    };

    for addr in &config.listen {
        match swarm.listen_on(addr.clone()) {
            Ok(_) => info!(%addr, "network: requesting listen"),
            Err(e) => error!(%addr, error = %e, "network: listen failed"),
        }
    }

    for addr in &config.bootstrap {
        match swarm.dial(addr.clone()) {
            Ok(_) => info!(%addr, "network: dialing bootstrap"),
            Err(e) => warn!(%addr, error = %e, "network: dial failed"),
        }
    }

    // Outbound request tracking. Every outbound request_response
    // call stashes its reply Sender here keyed by libp2p's
    // OutboundRequestId; the matching response (or an
    // OutboundFailure) clears the entry and forwards the payload
    // to the caller. One map for invoke + sync because each
    // RequestId is unique across all outbound traffic on the
    // behaviour.
    let mut outbound_replies: HashMap<
        request_response::OutboundRequestId,
        OutboundReply,
    > = HashMap::new();

    // Inbound dispatch path: blocking tasks complete asynchronously
    // and need to push (response_channel, frame) back to the swarm
    // so it can call send_response. The select! arm below pulls
    // from this channel.
    let (response_tx, mut response_rx) =
        async_mpsc::unbounded_channel::<(request_response::ResponseChannel<Frame>, Frame)>();

    // Per-replication-group hint senders. The agent's sync_loop
    // registers itself once on startup; gossipsub head announcements
    // route through here to the matching sync_loop, which then
    // performs an immediate fetch from the publisher.
    let mut hint_senders: HashMap<[u8; 32], std_mpsc::Sender<PeerId>> = HashMap::new();

    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                handle_swarm_event(
                    &mut swarm, event, local_prefix,
                    &prefix_map, &listen_addrs, &inbox_tx,
                    &mut outbound_replies,
                    &invoke_dispatcher,
                    &sync_provider,
                    &raft_handlers,
                    &manifest_provider,
                    &response_tx,
                    &hint_senders,
                );
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(NetworkCmd::Connect(addr)) => {
                        match swarm.dial(addr.clone()) {
                            Ok(_) => info!(%addr, "network: dialing peer"),
                            Err(e) => warn!(%addr, error = %e, "network: dial failed"),
                        }
                    }
                    Some(NetworkCmd::SendTell { target_peer, from, to, payload }) => {
                        let frame = Frame::Tell { from, to, payload };
                        let _id = swarm
                            .behaviour_mut()
                            .req_resp
                            .send_request(&target_peer, frame);
                        debug!(%target_peer, from, to, "network: sent Tell");
                    }
                    Some(NetworkCmd::SendInvoke {
                        target_peer, from, to, chain, msg, reply,
                    }) => {
                        let frame = Frame::InvokeRequest { from, to, chain, msg };
                        let req_id = swarm
                            .behaviour_mut()
                            .req_resp
                            .send_request(&target_peer, frame);
                        outbound_replies.insert(req_id, OutboundReply::Invoke(reply));
                        debug!(%target_peer, from, to, "network: sent InvokeRequest");
                    }
                    Some(NetworkCmd::SendFetchHeads {
                        target_peer, replication_id, reply,
                    }) => {
                        let frame = Frame::FetchHeads { replication_id };
                        let req_id = swarm
                            .behaviour_mut()
                            .req_resp
                            .send_request(&target_peer, frame);
                        outbound_replies.insert(req_id, OutboundReply::Heads(reply));
                        debug!(%target_peer, "network: sent FetchHeads");
                    }
                    Some(NetworkCmd::SendFetchNode {
                        target_peer, replication_id, cid, reply,
                    }) => {
                        let frame = Frame::FetchNode { replication_id, cid };
                        let req_id = swarm
                            .behaviour_mut()
                            .req_resp
                            .send_request(&target_peer, frame);
                        outbound_replies.insert(req_id, OutboundReply::Node(reply));
                        debug!(%target_peer, "network: sent FetchNode");
                    }
                    Some(NetworkCmd::SubscribeRep { replication_id }) => {
                        let topic = gossip_topic(&replication_id);
                        match swarm.behaviour_mut().gossip.subscribe(&topic) {
                            Ok(true) => debug!(
                                topic = %topic,
                                "network: subscribed to replication topic",
                            ),
                            Ok(false) => {} // already subscribed
                            Err(e) => warn!(
                                topic = %topic,
                                error = %e,
                                "network: subscribe failed",
                            ),
                        }
                    }
                    Some(NetworkCmd::PublishHeads { replication_id, roots }) => {
                        let topic = gossip_topic(&replication_id);
                        let frame = Frame::Heads { replication_id, roots };
                        let bytes = frame.encode();
                        match swarm.behaviour_mut().gossip.publish(topic.clone(), bytes) {
                            Ok(_) => {}
                            // NoPeersSubscribedToTopic is the common
                            // case at startup before the topic mesh
                            // forms — not a real error, the next sync
                            // tick still drives convergence via the
                            // request_response fallback.
                            Err(gossipsub::PublishError::NoPeersSubscribedToTopic) => {}
                            Err(e) => debug!(
                                topic = %topic,
                                error = ?e,
                                "network: publish heads (transient)",
                            ),
                        }
                    }
                    Some(NetworkCmd::RegisterHintSender { replication_id, sender }) => {
                        hint_senders.insert(replication_id, sender);
                    }
                    Some(NetworkCmd::SendRaftAppend {
                        target_peer,
                        replication_id,
                        term,
                        leader_prefix,
                        prev_log_index,
                        prev_log_term,
                        leader_commit,
                        entries,
                        reply,
                    }) => {
                        let frame = Frame::RaftAppendReq {
                            replication_id,
                            term,
                            leader_prefix,
                            prev_log_index,
                            prev_log_term,
                            leader_commit,
                            entries,
                        };
                        let req_id = swarm
                            .behaviour_mut()
                            .req_resp
                            .send_request(&target_peer, frame);
                        outbound_replies.insert(req_id, OutboundReply::RaftAppend(reply));
                        debug!(%target_peer, term, "network: sent RaftAppend");
                    }
                    Some(NetworkCmd::SendRaftVote {
                        target_peer,
                        replication_id,
                        term,
                        candidate_prefix,
                        last_log_index,
                        last_log_term,
                        reply,
                    }) => {
                        let frame = Frame::RaftVoteReq {
                            replication_id,
                            term,
                            candidate_prefix,
                            last_log_index,
                            last_log_term,
                        };
                        let req_id = swarm
                            .behaviour_mut()
                            .req_resp
                            .send_request(&target_peer, frame);
                        outbound_replies.insert(req_id, OutboundReply::RaftVote(reply));
                        debug!(%target_peer, term, "network: sent RaftVote");
                    }
                    Some(NetworkCmd::SendRaftInstallSnapshot {
                        target_peer,
                        replication_id,
                        term,
                        leader_prefix,
                        last_included_index,
                        last_included_term,
                        snapshot,
                        reply,
                    }) => {
                        let frame = Frame::RaftInstallSnapshotReq {
                            replication_id,
                            term,
                            leader_prefix,
                            last_included_index,
                            last_included_term,
                            snapshot,
                        };
                        let req_id = swarm
                            .behaviour_mut()
                            .req_resp
                            .send_request(&target_peer, frame);
                        outbound_replies.insert(
                            req_id,
                            OutboundReply::RaftInstallSnapshot(reply),
                        );
                        debug!(%target_peer, term, last_included_index,
                            "network: sent RaftInstallSnapshot");
                    }
                    Some(NetworkCmd::SendRaftJoin {
                        target_peer,
                        replication_id,
                        joiner_prefix,
                        reply,
                    }) => {
                        let frame = Frame::RaftJoinReq {
                            replication_id,
                            joiner_prefix,
                        };
                        let req_id = swarm
                            .behaviour_mut()
                            .req_resp
                            .send_request(&target_peer, frame);
                        outbound_replies.insert(req_id, OutboundReply::RaftJoin(reply));
                        debug!(%target_peer, joiner_prefix, "network: sent RaftJoinReq");
                    }
                    Some(NetworkCmd::SendManifestReq { target_peer, reply }) => {
                        let req_id = swarm
                            .behaviour_mut()
                            .req_resp
                            .send_request(&target_peer, Frame::ManifestReq);
                        outbound_replies.insert(req_id, OutboundReply::Manifest(reply));
                        debug!(%target_peer, "network: sent ManifestReq");
                    }
                    Some(NetworkCmd::SendRaftStatus {
                        target_peer,
                        replication_id,
                        reply,
                    }) => {
                        let req_id = swarm
                            .behaviour_mut()
                            .req_resp
                            .send_request(
                                &target_peer,
                                Frame::RaftStatusReq { replication_id },
                            );
                        outbound_replies.insert(req_id, OutboundReply::RaftStatus(reply));
                        debug!(%target_peer, "network: sent RaftStatusReq");
                    }
                    Some(NetworkCmd::Shutdown) | None => {
                        info!("network: shutting down");
                        break;
                    }
                }
            }
            Some((channel, frame)) = response_rx.recv() => {
                if swarm
                    .behaviour_mut()
                    .req_resp
                    .send_response(channel, frame)
                    .is_err()
                {
                    warn!("network: deferred response failed (channel closed)");
                }
            }
        }
    }
}

fn build_swarm(
    keypair: identity::Keypair,
) -> Result<Swarm<VosBehaviour>, Box<dyn std::error::Error + Send + Sync>> {
    let local_peer_id = PeerId::from(keypair.public());
    let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let mdns_cfg = mdns::Config::default();
            let mdns = mdns::tokio::Behaviour::new(mdns_cfg, local_peer_id)
                .map_err::<Box<dyn std::error::Error + Send + Sync>, _>(|e| Box::new(e))?;
            let ping = ping::Behaviour::default();
            let identify = identify::Behaviour::new(identify::Config::new(
                "/vos/0.1.0".into(),
                key.public(),
            ));
            let req_resp = request_response::Behaviour::with_codec(
                VosCodec,
                std::iter::once((PROTOCOL, ProtocolSupport::Full)),
                request_response::Config::default(),
            );
            // Gossipsub: one mesh per replication group. We sign
            // messages with the local keypair so peers can attest
            // who published a head announcement; that lets
            // `handle_gossipsub_event` route the resulting hint
            // back to the right peer for the BFS fetch.
            let gossip_cfg = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(1))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .build()
                .map_err::<Box<dyn std::error::Error + Send + Sync>, _>(|e| {
                    format!("gossipsub config: {e}").into()
                })?;
            let gossip = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossip_cfg,
            )
            .map_err::<Box<dyn std::error::Error + Send + Sync>, _>(|e| {
                format!("gossipsub: {e}").into()
            })?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(VosBehaviour {
                mdns,
                ping,
                identify,
                req_resp,
                gossip,
            })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    Ok(swarm)
}

fn handle_swarm_event(
    swarm: &mut Swarm<VosBehaviour>,
    event: SwarmEvent<VosBehaviourEvent>,
    local_prefix: u16,
    prefix_map: &PrefixMap,
    listen_addrs: &ListenAddrs,
    inbox: &std_mpsc::Sender<InboundTell>,
    outbound_replies: &mut HashMap<request_response::OutboundRequestId, OutboundReply>,
    invoke_dispatcher: &Arc<Mutex<Option<Arc<dyn InvokeDispatcher>>>>,
    sync_provider: &Arc<Mutex<Option<Arc<dyn SyncProvider>>>>,
    raft_handlers: &RaftHandlerMap,
    manifest_provider: &Arc<Mutex<Option<Arc<dyn ManifestProvider>>>>,
    response_tx: &async_mpsc::UnboundedSender<(request_response::ResponseChannel<Frame>, Frame)>,
    hint_senders: &HashMap<[u8; 32], std_mpsc::Sender<PeerId>>,
) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            info!(%address, "network: listening on");
            if let Ok(mut v) = listen_addrs.lock() {
                if !v.contains(&address) {
                    v.push(address);
                }
            }
        }
        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
            info!(%peer_id, ?endpoint, "network: peer connected");
            // Initiate the Hello handshake from the dialer side.
            // The listener's reply rides back as the response, so
            // both sides learn each other's prefix from one round
            // trip. Doing it from both sides would be harmless but
            // wasteful.
            if endpoint.is_dialer() {
                let _ = swarm.behaviour_mut().req_resp.send_request(
                    &peer_id,
                    Frame::Hello { node_prefix: local_prefix },
                );
            }
        }
        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
            info!(%peer_id, ?cause, "network: peer disconnected");
        }
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            warn!(?peer_id, error = %error, "network: outgoing connection failed");
        }
        SwarmEvent::Behaviour(VosBehaviourEvent::Mdns(mdns::Event::Discovered(peers))) => {
            for (peer_id, addr) in peers {
                info!(%peer_id, %addr, "network: mDNS discovered peer; dialing");
                let _ = swarm.dial(addr);
            }
        }
        SwarmEvent::Behaviour(VosBehaviourEvent::Mdns(mdns::Event::Expired(peers))) => {
            for (peer_id, _addr) in peers {
                debug!(%peer_id, "network: mDNS peer expired");
            }
        }
        SwarmEvent::Behaviour(VosBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
            debug!(%peer_id, agent = %info.agent_version, "network: identify received");
        }
        SwarmEvent::Behaviour(VosBehaviourEvent::ReqResp(rr_event)) => {
            handle_req_resp(
                swarm, rr_event, local_prefix, prefix_map, inbox,
                outbound_replies, invoke_dispatcher, sync_provider,
                raft_handlers, manifest_provider, response_tx,
            );
        }
        SwarmEvent::Behaviour(VosBehaviourEvent::Gossip(g_event)) => {
            handle_gossipsub_event(g_event, hint_senders);
        }
        _ => {}
    }
}

fn handle_req_resp(
    swarm: &mut Swarm<VosBehaviour>,
    event: request_response::Event<Frame, Frame>,
    local_prefix: u16,
    prefix_map: &PrefixMap,
    inbox: &std_mpsc::Sender<InboundTell>,
    outbound_replies: &mut HashMap<request_response::OutboundRequestId, OutboundReply>,
    invoke_dispatcher: &Arc<Mutex<Option<Arc<dyn InvokeDispatcher>>>>,
    sync_provider: &Arc<Mutex<Option<Arc<dyn SyncProvider>>>>,
    raft_handlers: &RaftHandlerMap,
    manifest_provider: &Arc<Mutex<Option<Arc<dyn ManifestProvider>>>>,
    response_tx: &async_mpsc::UnboundedSender<(request_response::ResponseChannel<Frame>, Frame)>,
) {
    use request_response::{Event, Message};

    match event {
        Event::Message { peer, message, .. } => match message {
            Message::Request { request, channel, .. } => {
                match request {
                    Frame::Hello { node_prefix } => {
                        record_prefix(prefix_map, node_prefix, peer);
                        let _ = swarm.behaviour_mut().req_resp.send_response(
                            channel,
                            Frame::Hello { node_prefix: local_prefix },
                        );
                    }
                    Frame::Tell { from, to, payload } => {
                        if inbox.send(InboundTell { from, to, payload }).is_err() {
                            warn!(%peer, "network: local inbox closed; dropping inbound Tell");
                        }
                        let _ = swarm
                            .behaviour_mut()
                            .req_resp
                            .send_response(channel, Frame::Ack);
                    }
                    Frame::InvokeRequest { from, to, chain, msg } => {
                        // Hand off to a blocking task: the dispatcher's
                        // reply channel uses std::sync::mpsc, which would
                        // park the runtime if awaited inline. The task
                        // calls back with (channel, InvokeReply) which the
                        // swarm select! arm forwards via send_response.
                        let dispatcher = invoke_dispatcher.lock().ok().and_then(|g| g.clone());
                        let response_tx = response_tx.clone();
                        tokio::task::spawn_blocking(move || {
                            let payload = match dispatcher {
                                Some(d) => d.dispatch(from, to, chain, msg),
                                None => {
                                    warn!(
                                        from, to,
                                        "network: inbound InvokeRequest with no \
                                         dispatcher installed; replying empty",
                                    );
                                    Vec::new()
                                }
                            };
                            let _ = response_tx
                                .send((channel, Frame::InvokeReply { payload }));
                        });
                    }
                    Frame::FetchHeads { replication_id } => {
                        // Sync reads are quick redb txns; serve them
                        // inline rather than spawning a blocking task.
                        let provider = sync_provider.lock().ok().and_then(|g| g.clone());
                        let roots = provider
                            .as_ref()
                            .and_then(|p| p.roots(&replication_id))
                            .unwrap_or_default();
                        let _ = swarm.behaviour_mut().req_resp.send_response(
                            channel,
                            Frame::Heads { replication_id, roots },
                        );
                    }
                    Frame::FetchNode { replication_id, cid } => {
                        let provider = sync_provider.lock().ok().and_then(|g| g.clone());
                        let node = provider
                            .as_ref()
                            .and_then(|p| p.get_node(&replication_id, &cid));
                        let _ = swarm
                            .behaviour_mut()
                            .req_resp
                            .send_response(channel, Frame::NodeReply { node });
                    }
                    Frame::RaftAppendReq {
                        replication_id,
                        term,
                        leader_prefix,
                        prev_log_index,
                        prev_log_term,
                        leader_commit,
                        entries,
                    } => {
                        // Hand off to a blocking task: handlers may
                        // do redb writes (append entries, advance
                        // last_applied), which would park the
                        // current_thread runtime if awaited inline.
                        // Routing is per-replication-group: we look
                        // up the handler keyed by `replication_id`
                        // so multiple Raft clusters can coexist on
                        // one node.
                        let handler = raft_handlers
                            .lock()
                            .ok()
                            .and_then(|g| g.get(&replication_id).cloned());
                        let response_tx = response_tx.clone();
                        tokio::task::spawn_blocking(move || {
                            let resp = match handler {
                                Some(h) => h.append_entries(
                                    &replication_id,
                                    leader_prefix,
                                    term,
                                    prev_log_index,
                                    prev_log_term,
                                    leader_commit,
                                    entries,
                                ),
                                None => {
                                    warn!(
                                        leader_prefix,
                                        rep_id = format!("{:02x}{:02x}..", replication_id[0], replication_id[1]),
                                        "network: inbound RaftAppendReq for unknown \
                                         replication group; replying success=false",
                                    );
                                    RaftAppendResult {
                                        term,
                                        success: false,
                                        match_index: 0,
                                    }
                                }
                            };
                            let _ = response_tx.send((
                                channel,
                                Frame::RaftAppendResp {
                                    term: resp.term,
                                    success: resp.success,
                                    match_index: resp.match_index,
                                },
                            ));
                        });
                    }
                    Frame::RaftVoteReq {
                        replication_id,
                        term,
                        candidate_prefix,
                        last_log_index,
                        last_log_term,
                    } => {
                        // Vote logic touches redb (writes voted_for /
                        // current_term), so dispatch on a blocking task.
                        // Routed by `replication_id` like AppendEntries.
                        let handler = raft_handlers
                            .lock()
                            .ok()
                            .and_then(|g| g.get(&replication_id).cloned());
                        let response_tx = response_tx.clone();
                        tokio::task::spawn_blocking(move || {
                            let resp = match handler {
                                Some(h) => h.request_vote(
                                    &replication_id,
                                    candidate_prefix,
                                    term,
                                    last_log_index,
                                    last_log_term,
                                ),
                                None => {
                                    warn!(
                                        candidate_prefix,
                                        rep_id = format!("{:02x}{:02x}..", replication_id[0], replication_id[1]),
                                        "network: inbound RaftVoteReq for unknown \
                                         replication group; vote_granted=false",
                                    );
                                    RaftVoteResult {
                                        term,
                                        vote_granted: false,
                                    }
                                }
                            };
                            let _ = response_tx.send((
                                channel,
                                Frame::RaftVoteResp {
                                    term: resp.term,
                                    vote_granted: resp.vote_granted,
                                },
                            ));
                        });
                    }
                    Frame::RaftInstallSnapshotReq {
                        replication_id,
                        term,
                        leader_prefix,
                        last_included_index,
                        last_included_term,
                        snapshot,
                    } => {
                        // Install logic writes redb (state row +
                        // raft_meta + raft_log truncate), so a
                        // blocking task is the right shape. Routed
                        // by `replication_id` like the other Raft
                        // RPCs.
                        let handler = raft_handlers
                            .lock()
                            .ok()
                            .and_then(|g| g.get(&replication_id).cloned());
                        let response_tx = response_tx.clone();
                        tokio::task::spawn_blocking(move || {
                            let resp = match handler {
                                Some(h) => h.install_snapshot(
                                    &replication_id,
                                    leader_prefix,
                                    term,
                                    last_included_index,
                                    last_included_term,
                                    snapshot,
                                ),
                                None => {
                                    warn!(
                                        leader_prefix,
                                        rep_id = format!("{:02x}{:02x}..", replication_id[0], replication_id[1]),
                                        "network: inbound RaftInstallSnapshotReq for unknown \
                                         replication group; replying with our term",
                                    );
                                    RaftInstallSnapshotResult { term }
                                }
                            };
                            let _ = response_tx.send((
                                channel,
                                Frame::RaftInstallSnapshotResp { term: resp.term },
                            ));
                        });
                    }
                    Frame::RaftJoinReq { replication_id, joiner_prefix } => {
                        // Join requests can call `change_membership`,
                        // which writes the joint-config redb row. Off
                        // the swarm thread.
                        let handler = raft_handlers
                            .lock()
                            .ok()
                            .and_then(|g| g.get(&replication_id).cloned());
                        let response_tx = response_tx.clone();
                        tokio::task::spawn_blocking(move || {
                            let result = match handler {
                                Some(h) => h.handle_join(&replication_id, joiner_prefix),
                                None => RaftJoinResult::UnknownGroup,
                            };
                            let _ = response_tx.send((
                                channel,
                                Frame::RaftJoinResp { result },
                            ));
                        });
                    }
                    Frame::ManifestReq => {
                        // Manifest provider just reads in-memory
                        // bytes; serve inline.
                        let provider = manifest_provider
                            .lock()
                            .ok()
                            .and_then(|g| g.clone());
                        let (toml_bytes, blobs) = provider
                            .and_then(|p| p.manifest())
                            .unwrap_or_default();
                        let _ = swarm.behaviour_mut().req_resp.send_response(
                            channel,
                            Frame::ManifestResp { toml_bytes, blobs },
                        );
                    }
                    Frame::RaftStatusReq { replication_id } => {
                        // Status query needs a snapshot from the
                        // worker — that round-trips through its
                        // inbox, so dispatch on a blocking task.
                        let handler = raft_handlers
                            .lock()
                            .ok()
                            .and_then(|g| g.get(&replication_id).cloned());
                        let response_tx = response_tx.clone();
                        tokio::task::spawn_blocking(move || {
                            let reply = match handler {
                                Some(h) => h.handle_status(&replication_id),
                                None => RaftStatusReply::absent(),
                            };
                            let _ = response_tx.send((
                                channel,
                                Frame::RaftStatusResp {
                                    present: reply.present,
                                    role: reply.role.to_wire(),
                                    current_term: reply.current_term,
                                    commit_index: reply.commit_index,
                                    last_log_index: reply.last_log_index,
                                    members: reply.members,
                                    leader_hint: reply.leader_hint,
                                },
                            ));
                        });
                    }
                    other => {
                        warn!(%peer, ?other, "network: unexpected frame in request slot");
                        let _ = swarm
                            .behaviour_mut()
                            .req_resp
                            .send_response(channel, Frame::Ack);
                    }
                }
            }
            Message::Response { response, request_id, .. } => {
                let pending = outbound_replies.remove(&request_id);
                match (response, pending) {
                    (Frame::Hello { node_prefix }, _) => {
                        record_prefix(prefix_map, node_prefix, peer);
                    }
                    (Frame::Ack, _) => {
                        debug!(%peer, "network: Tell ack received");
                    }
                    (Frame::InvokeReply { payload }, Some(OutboundReply::Invoke(tx))) => {
                        let _ = tx.send(payload);
                    }
                    (Frame::Heads { roots, .. }, Some(OutboundReply::Heads(tx))) => {
                        let _ = tx.send(roots);
                    }
                    (Frame::NodeReply { node }, Some(OutboundReply::Node(tx))) => {
                        let _ = tx.send(node);
                    }
                    (
                        Frame::RaftAppendResp { term, success, match_index },
                        Some(OutboundReply::RaftAppend(tx)),
                    ) => {
                        let _ = tx.send(RaftAppendResult {
                            term,
                            success,
                            match_index,
                        });
                    }
                    (
                        Frame::RaftVoteResp { term, vote_granted },
                        Some(OutboundReply::RaftVote(tx)),
                    ) => {
                        let _ = tx.send(RaftVoteResult { term, vote_granted });
                    }
                    (
                        Frame::RaftInstallSnapshotResp { term },
                        Some(OutboundReply::RaftInstallSnapshot(tx)),
                    ) => {
                        let _ = tx.send(RaftInstallSnapshotResult { term });
                    }
                    (
                        Frame::RaftJoinResp { result },
                        Some(OutboundReply::RaftJoin(tx)),
                    ) => {
                        let _ = tx.send(result);
                    }
                    (
                        Frame::ManifestResp { toml_bytes, blobs },
                        Some(OutboundReply::Manifest(tx)),
                    ) => {
                        let _ = tx.send((toml_bytes, blobs));
                    }
                    (
                        Frame::RaftStatusResp {
                            present, role, current_term, commit_index,
                            last_log_index, members, leader_hint,
                        },
                        Some(OutboundReply::RaftStatus(tx)),
                    ) => {
                        let _ = tx.send(RaftStatusReply {
                            present,
                            role: RaftRole::from_wire(role),
                            current_term,
                            commit_index,
                            last_log_index,
                            members,
                            leader_hint,
                        });
                    }
                    (other, _) => {
                        warn!(%peer, ?other, "network: response shape mismatched pending request");
                    }
                }
            }
        },
        Event::OutboundFailure { peer, request_id, error, .. } => {
            warn!(%peer, error = %error, "network: outbound request failed");
            // Drop the reply Sender so the caller's recv yields
            // Disconnected — surfaces as None / NotFound.
            let _ = outbound_replies.remove(&request_id);
        }
        Event::InboundFailure { peer, error, .. } => {
            warn!(%peer, error = %error, "network: inbound request failed");
        }
        Event::ResponseSent { .. } => {}
    }
}

/// Gossipsub topic name for a replication group.
fn gossip_topic(rep_id: &[u8; 32]) -> gossipsub::IdentTopic {
    let mut hex = String::with_capacity(64);
    for b in rep_id {
        use core::fmt::Write;
        let _ = write!(&mut hex, "{:02x}", b);
    }
    gossipsub::IdentTopic::new(format!("vos/sync/{hex}"))
}

fn handle_gossipsub_event(
    event: gossipsub::Event,
    hint_senders: &HashMap<[u8; 32], std_mpsc::Sender<PeerId>>,
) {
    match event {
        gossipsub::Event::Message { propagation_source, message, .. } => {
            // Decode the published frame; expect Heads with a
            // replication_id matching the topic. We use rep_id
            // from the frame as the routing key (the topic's hex
            // is derivable but the frame's bytes are
            // authoritative).
            let frame = match Frame::decode(&message.data) {
                Ok(f) => f,
                Err(e) => {
                    warn!(error = %e, "gossipsub: bad frame, dropping");
                    return;
                }
            };
            if let Frame::Heads { replication_id, .. } = frame {
                if let Some(sender) = hint_senders.get(&replication_id) {
                    let _ = sender.send(propagation_source);
                }
            } else {
                warn!(?frame, "gossipsub: unexpected frame on sync topic");
            }
        }
        _ => {}
    }
}

fn record_prefix(map: &PrefixMap, prefix: u16, peer: PeerId) {
    let mut m = match map.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    match m.insert(prefix, peer) {
        Some(prev) if prev == peer => {}
        Some(prev) => warn!(
            prefix = format!("{prefix:#06x}"),
            previous = %prev,
            current = %peer,
            "network: prefix re-assigned to a different peer (collision?)",
        ),
        None => info!(
            prefix = format!("{prefix:#06x}"),
            %peer,
            "network: learned peer prefix",
        ),
    }
}

/// Derive the 16-bit `node_prefix` for this node from its libp2p
/// peer ID. Computed as the first two bytes of `blake2b(peer_id
/// bytes)` interpreted little-endian, giving a uniform u16.
///
/// The prefix is what every `ServiceId` allocated locally embeds
/// in its top 16 bits; remote peers learn it via the [`Frame::Hello`]
/// handshake on first contact.
///
/// Collisions are possible (1 in 65 536 per peer pair) — they don't
/// happen in practice for small networks but will need real
/// addressing once kunekt grows past hyperspace-sized clusters.
/// That's a Cycle 3+ concern; for now we log a warning when the
/// prefix map sees a collision.
pub fn derive_node_prefix(peer_id: &PeerId) -> u16 {
    let hash = blake2b_simd::Params::new()
        .hash_length(2)
        .to_state()
        .update(&peer_id.to_bytes())
        .finalize();
    let bytes = hash.as_bytes();
    u16::from_le_bytes([bytes[0], bytes[1]])
}

/// Resolve the manifest's `[node].identity` field into a libp2p
/// keypair.
///
/// - `None` or `Some("auto")` — derive (or load) a keypair stored
///   at `{data_dir}/node.key`. Persisted across runs so the
///   node's PeerId is stable.
/// - `Some(path)` — load the keypair from that file (protobuf
///   encoding produced by `Keypair::to_protobuf_encoding`).
pub fn load_or_generate_identity(
    spec: Option<&str>,
    data_dir: Option<&Path>,
) -> Result<identity::Keypair, String> {
    match spec {
        Some("auto") | None => {
            let dir = data_dir.unwrap_or(Path::new("."));
            let key_path: PathBuf = dir.join("node.key");
            if key_path.exists() {
                let bytes = std::fs::read(&key_path)
                    .map_err(|e| format!("read {}: {e}", key_path.display()))?;
                identity::Keypair::from_protobuf_encoding(&bytes)
                    .map_err(|e| format!("decode {}: {e}", key_path.display()))
            } else {
                let kp = identity::Keypair::generate_ed25519();
                let bytes = kp
                    .to_protobuf_encoding()
                    .map_err(|e| format!("encode keypair: {e}"))?;
                if !dir.exists() {
                    std::fs::create_dir_all(dir)
                        .map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
                }
                std::fs::write(&key_path, &bytes)
                    .map_err(|e| format!("write {}: {e}", key_path.display()))?;
                info!(path = %key_path.display(), "network: generated new node identity");
                Ok(kp)
            }
        }
        Some(path) => {
            let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
            identity::Keypair::from_protobuf_encoding(&bytes)
                .map_err(|e| format!("decode {path}: {e}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_node_prefix_is_deterministic() {
        let kp = identity::Keypair::generate_ed25519();
        let pid = PeerId::from(kp.public());
        let p1 = derive_node_prefix(&pid);
        let p2 = derive_node_prefix(&pid);
        assert_eq!(p1, p2);
    }

    #[test]
    fn derive_node_prefix_differs_for_different_peers() {
        // Two random keypairs almost always hash to different prefixes.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..16 {
            let kp = identity::Keypair::generate_ed25519();
            let pid = PeerId::from(kp.public());
            seen.insert(derive_node_prefix(&pid));
        }
        // 16 random u16s collide vanishingly rarely.
        assert!(seen.len() >= 15, "got {} unique prefixes from 16 keys", seen.len());
    }

    #[test]
    fn two_networks_exchange_tell_and_prefix() {
        // Bring up two networks bound to ephemeral 127.0.0.1
        // ports, have B dial A explicitly (no mDNS — keeps the
        // test deterministic and self-contained), then verify:
        //   1. Both sides learn each other's node_prefix via the
        //      Hello round trip on `ConnectionEstablished`.
        //   2. A Tell sent from one side lands in the other's
        //      inbox with the correct from/to/payload.
        //
        // Re-runs from the same crate share the LAN with any
        // long-lived libp2p instance, so we explicitly avoid
        // mDNS and never rely on it for rendezvous here.

        let kp_a = identity::Keypair::generate_ed25519();
        let kp_b = identity::Keypair::generate_ed25519();
        let prefix_a = 0xAAAA;
        let prefix_b = 0xBBBB;

        let listen_addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

        let net_a = Network::start(NetworkConfig {
            keypair: kp_a,
            local_prefix: prefix_a,
            listen: vec![listen_addr.clone()],
            bootstrap: vec![],
        });
        let inbox_a_rx = net_a.take_inbox().expect("first take");

        // Wait until A reports a bound address — without this, B
        // has nothing to dial.
        let a_addr = wait_for(|| net_a.listen_addrs().into_iter().next(), Duration::from_secs(5))
            .expect("net_a should have bound a listen address");
        let a_peer_id = net_a.peer_id();
        let a_dial: Multiaddr = a_addr.with(libp2p::multiaddr::Protocol::P2p(a_peer_id));

        let net_b = Network::start(NetworkConfig {
            keypair: kp_b,
            local_prefix: prefix_b,
            listen: vec![listen_addr],
            bootstrap: vec![a_dial],
        });
        let inbox_b_rx = net_b.take_inbox().expect("first take");

        // Wait until both prefix maps populate (Hello handshake done).
        let ok = wait_for(
            || {
                if net_a.peer_for_prefix(prefix_b).is_some()
                    && net_b.peer_for_prefix(prefix_a).is_some()
                {
                    Some(())
                } else {
                    None
                }
            },
            Duration::from_secs(10),
        );
        assert!(
            ok.is_some(),
            "Hello handshake didn't complete within deadline",
        );
        assert_eq!(net_a.peer_for_prefix(prefix_b), Some(net_b.peer_id()));
        assert_eq!(net_b.peer_for_prefix(prefix_a), Some(net_a.peer_id()));

        // A → B
        let target_b = net_a.peer_for_prefix(prefix_b).unwrap();
        net_a.send_tell(target_b, 0xDEADBEEF, 0xCAFEBABE, b"hello B".to_vec());
        let inbound = inbox_b_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("Tell to B");
        assert_eq!(inbound.from, 0xDEADBEEF);
        assert_eq!(inbound.to, 0xCAFEBABE);
        assert_eq!(inbound.payload, b"hello B");

        // B → A (symmetric)
        let target_a = net_b.peer_for_prefix(prefix_a).unwrap();
        net_b.send_tell(target_a, 1, 2, b"hello A".to_vec());
        let inbound = inbox_a_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("Tell to A");
        assert_eq!(inbound.payload, b"hello A");

        net_a.join();
        net_b.join();
    }

    fn wait_for<T>(mut probe: impl FnMut() -> Option<T>, deadline: Duration) -> Option<T> {
        let until = std::time::Instant::now() + deadline;
        loop {
            if let Some(v) = probe() {
                return Some(v);
            }
            if std::time::Instant::now() >= until {
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Cycle 3 convergence: replica A is driven by two commits,
    /// replica B (empty) automatically pulls A's DAG via the
    /// background sync ticker. After a brief settle period,
    /// re-open B's redb and verify `replay_logs` reproduces A's
    /// history bit-for-bit.
    #[test]
    fn crdt_replicas_converge_via_sync_ticker() {
        use crate::commit::{CommitStrategy, CrdtCommit};
        use crate::effect_log::EffectLog;
        use crate::node::VosNode;

        let kp_a = identity::Keypair::generate_ed25519();
        let kp_b = identity::Keypair::generate_ed25519();
        let prefix_a = derive_node_prefix(&PeerId::from(kp_a.public()));
        let prefix_b = derive_node_prefix(&PeerId::from(kp_b.public()));
        let listen_addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

        let net_a = Network::start(NetworkConfig {
            keypair: kp_a,
            local_prefix: prefix_a,
            listen: vec![listen_addr.clone()],
            bootstrap: vec![],
        });
        let a_listen = wait_for(
            || net_a.listen_addrs().into_iter().next(),
            Duration::from_secs(5),
        )
        .expect("net_a binds");
        let a_dial: Multiaddr = a_listen.with(libp2p::multiaddr::Protocol::P2p(net_a.peer_id()));

        let net_b = Network::start(NetworkConfig {
            keypair: kp_b,
            local_prefix: prefix_b,
            listen: vec![listen_addr],
            bootstrap: vec![a_dial],
        });

        let rep_id = [0xCDu8; 32];
        let dir = std::env::temp_dir().join(format!(
            "vos_sync_conv_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path_a = dir.join("a.redb");
        let path_b = dir.join("b.redb");

        // Two VosNodes, each with a test replica + a sync ticker
        // (install_test_replica spawns one).
        let mut node_a = VosNode::with_prefix(prefix_a);
        let slot_a = node_a.install_test_replica(rep_id, &path_a);
        let mut node_b = VosNode::with_prefix(prefix_b);
        let slot_b = node_b.install_test_replica(rep_id, &path_b);

        // Drive A: two CRDT commits.
        let log1 = EffectLog::for_msg(b"first".to_vec());
        let log2 = EffectLog::for_msg(b"second".to_vec());
        {
            let mut cc_a = CrdtCommit::from_db_arc_locked(
                slot_a.db.clone(),
                slot_a.commit_lock.clone(),
            );
            cc_a.commit_with_log(b"v1", &log1).unwrap();
            cc_a.commit_with_log(b"v2", &log2).unwrap();
            assert_eq!(cc_a.root_bytes().len(), 1);
        }

        // Attach the networks. This is when the sync ticker can
        // actually do anything — until shared_network is Some it
        // just sleeps.
        node_a.attach_network(net_a);
        node_b.attach_network(net_b);

        // Wait for the Hello round trip + a few sync ticks. The
        // ticker fires every 250ms, so 2 seconds gives 6+ rounds —
        // plenty to cover a 2-node BFS of 2 DAG nodes.
        let convergence = wait_for(
            || {
                // Open a *fresh* CrdtCommit on B and check its
                // roots. The sync ticker writes through the same
                // redb file, so a fresh CrdtCommit picks up the
                // merged state.
                let cc = CrdtCommit::from_db_arc_locked(
                    slot_b.db.clone(),
                    slot_b.commit_lock.clone(),
                );
                if cc.root_bytes().is_empty() {
                    None
                } else {
                    Some(cc)
                }
            },
            Duration::from_secs(5),
        );
        let cc_b = convergence.expect("B should converge to A's heads");

        // Replay logs match A's history.
        let logs = cc_b.replay_logs().unwrap();
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0], log1);
        assert_eq!(logs[1], log2);

        // Roots match too.
        let cc_a = CrdtCommit::from_db_arc_locked(
            slot_a.db.clone(),
            slot_a.commit_lock.clone(),
        );
        assert_eq!(cc_a.root_bytes(), cc_b.root_bytes());

        let _ = node_a.collect();
        let _ = node_b.collect();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Slice 3b end-to-end: VosNode B has a CRDT replica registered
    /// in `crdt_replicas` (via the test helper) with some DAG
    /// nodes pre-populated; VosNode A asks via the network and
    /// reads them back through `NodeSyncProvider`.
    #[test]
    fn cross_node_sync_via_vosnode_replicas() {
        use crate::commit::{CommitStrategy, CrdtCommit};
        use crate::effect_log::EffectLog;
        use crate::node::VosNode;

        let kp_a = identity::Keypair::generate_ed25519();
        let kp_b = identity::Keypair::generate_ed25519();
        let prefix_a = derive_node_prefix(&PeerId::from(kp_a.public()));
        let prefix_b = derive_node_prefix(&PeerId::from(kp_b.public()));
        let listen_addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

        let net_a = Network::start(NetworkConfig {
            keypair: kp_a,
            local_prefix: prefix_a,
            listen: vec![listen_addr.clone()],
            bootstrap: vec![],
        });
        let a_listen = wait_for(
            || net_a.listen_addrs().into_iter().next(),
            Duration::from_secs(5),
        )
        .expect("net_a binds");
        let a_dial: Multiaddr = a_listen.with(libp2p::multiaddr::Protocol::P2p(net_a.peer_id()));

        let net_b = Network::start(NetworkConfig {
            keypair: kp_b,
            local_prefix: prefix_b,
            listen: vec![listen_addr],
            bootstrap: vec![a_dial],
        });

        // Build node B with a pre-populated replica, attach net_b.
        let mut node_b = VosNode::with_prefix(prefix_b);
        let rep_id = [0x99u8; 32];
        let dir_b = std::env::temp_dir().join(format!(
            "vos_sync_b_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir_b).unwrap();
        let db_path_b = dir_b.join("replica.redb");
        let _slot_b = node_b.install_test_replica(rep_id, &db_path_b);

        // Drive a couple of CRDT commits through a CrdtCommit
        // built from the same shared slot the sync layer reads.
        let slot_for_writes = node_b
            .crdt_replicas
            .lock()
            .unwrap()
            .get(&rep_id)
            .cloned()
            .unwrap();
        let mut cc = CrdtCommit::from_db_arc_locked(
            slot_for_writes.db,
            slot_for_writes.commit_lock,
        );
        cc.commit_with_log(b"v1", &EffectLog::for_msg(b"first".to_vec())).unwrap();
        cc.commit_with_log(b"v2", &EffectLog::for_msg(b"second".to_vec())).unwrap();
        let expected_root = cc.root_bytes()[0];
        let expected_node_bytes = cc.get_node_bytes(&expected_root).unwrap().unwrap();
        drop(cc);

        node_b.attach_network(net_b);

        // VosNode A — empty, just attached.
        let mut node_a = VosNode::with_prefix(prefix_a);
        node_a.attach_network(net_a);

        // From outside, reach into A's network (we can't because
        // attach_network moved it). Use the shared_network handle
        // VosNode keeps.
        let net_a_arc = node_a
            .shared_network
            .lock()
            .unwrap()
            .clone()
            .expect("net_a attached");

        wait_for(
            || net_a_arc.peer_for_prefix(prefix_b),
            Duration::from_secs(10),
        )
        .expect("Hello completes");
        let peer_b = net_a_arc.peer_for_prefix(prefix_b).unwrap();

        // Ask B for heads of the replication group.
        let heads = net_a_arc
            .fetch_heads(peer_b, rep_id)
            .recv_timeout(Duration::from_secs(5))
            .expect("FetchHeads reply");
        assert_eq!(heads, vec![expected_root]);

        // Point-fetch the root node.
        let node = net_a_arc
            .fetch_node(peer_b, rep_id, expected_root)
            .recv_timeout(Duration::from_secs(5))
            .expect("FetchNode reply");
        assert_eq!(node.as_deref(), Some(expected_node_bytes.as_slice()));

        let _ = node_a.collect();
        let _ = node_b.collect();
        let _ = std::fs::remove_dir_all(&dir_b);
    }

    /// Network-level test: gossipsub head announcements route a
    /// `Frame::Heads` published by A to a hint sender registered
    /// by B, with the publisher's PeerId surfaced as the hint
    /// payload. Proves the cycle-8 push path independently of
    /// the cycle-3 request_response fallback.
    #[test]
    fn gossipsub_head_announcement_hints_subscribers() {
        let kp_a = identity::Keypair::generate_ed25519();
        let kp_b = identity::Keypair::generate_ed25519();
        let listen_addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

        let net_a = Network::start(NetworkConfig {
            keypair: kp_a,
            local_prefix: 0xA0A0,
            listen: vec![listen_addr.clone()],
            bootstrap: vec![],
        });
        let a_listen = wait_for(
            || net_a.listen_addrs().into_iter().next(),
            Duration::from_secs(5),
        )
        .expect("net_a binds");
        let a_dial: Multiaddr = a_listen.with(libp2p::multiaddr::Protocol::P2p(net_a.peer_id()));

        let net_b = Network::start(NetworkConfig {
            keypair: kp_b,
            local_prefix: 0xB0B0,
            listen: vec![listen_addr],
            bootstrap: vec![a_dial],
        });

        let rep_id = [0x77u8; 32];
        let (hint_tx, hint_rx) = std_mpsc::channel::<PeerId>();
        net_b.register_hint_sender(rep_id, hint_tx);

        // Both sides subscribe — gossipsub needs a mesh of at
        // least one subscriber per side before publish actually
        // delivers anything.
        net_a.subscribe_rep(rep_id);
        net_b.subscribe_rep(rep_id);

        // Wait for the gossipsub heartbeat (1s) to form the
        // mesh, then publish from A. Retry the publish until B
        // sees the hint or the deadline expires.
        let until = std::time::Instant::now() + Duration::from_secs(10);
        let mut got: Option<PeerId> = None;
        while std::time::Instant::now() < until {
            net_a.publish_heads(rep_id, vec![[0xCDu8; 32]]);
            if let Ok(peer) = hint_rx.recv_timeout(Duration::from_millis(500)) {
                got = Some(peer);
                break;
            }
        }
        let publisher = got.expect("hint should arrive within deadline");
        assert_eq!(publisher, net_a.peer_id(), "hint should carry A's PeerId");

        net_a.join();
        net_b.join();
    }

    /// Network-level test: A asks B for the heads of a replication
    /// group and then point-fetches a DAG node by CID. Verifies
    /// the SyncProvider on B sees the requests and the responses
    /// round-trip through the request_response wire.
    #[test]
    fn cross_node_sync_fetch_heads_and_node() {
        struct StaticProvider {
            rep_id: [u8; 32],
            roots: Vec<[u8; 32]>,
            nodes: std::collections::BTreeMap<[u8; 32], Vec<u8>>,
        }

        impl SyncProvider for StaticProvider {
            fn roots(&self, replication_id: &[u8; 32]) -> Option<Vec<[u8; 32]>> {
                if replication_id == &self.rep_id {
                    Some(self.roots.clone())
                } else {
                    None
                }
            }
            fn get_node(&self, replication_id: &[u8; 32], cid: &[u8; 32]) -> Option<Vec<u8>> {
                if replication_id != &self.rep_id {
                    return None;
                }
                self.nodes.get(cid).cloned()
            }
        }

        let kp_a = identity::Keypair::generate_ed25519();
        let kp_b = identity::Keypair::generate_ed25519();
        let listen_addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

        let net_a = Network::start(NetworkConfig {
            keypair: kp_a,
            local_prefix: 0x0A0A,
            listen: vec![listen_addr.clone()],
            bootstrap: vec![],
        });
        let a_listen = wait_for(
            || net_a.listen_addrs().into_iter().next(),
            Duration::from_secs(5),
        )
        .expect("net_a binds");
        let a_dial: Multiaddr = a_listen.with(libp2p::multiaddr::Protocol::P2p(net_a.peer_id()));

        let net_b = Network::start(NetworkConfig {
            keypair: kp_b,
            local_prefix: 0x0B0B,
            listen: vec![listen_addr],
            bootstrap: vec![a_dial],
        });

        let rep_id = [0x42u8; 32];
        let cid_present = [0xAAu8; 32];
        let cid_missing = [0xCCu8; 32];
        let mut nodes = std::collections::BTreeMap::new();
        nodes.insert(cid_present, b"node-bytes-here".to_vec());

        net_b.set_sync_provider(Arc::new(StaticProvider {
            rep_id,
            roots: vec![cid_present],
            nodes,
        }));

        wait_for(
            || net_a.peer_for_prefix(net_b.local_prefix()),
            Duration::from_secs(10),
        )
        .expect("Hello completes");
        let peer_b = net_a.peer_for_prefix(net_b.local_prefix()).unwrap();

        // FetchHeads
        let heads_rx = net_a.fetch_heads(peer_b, rep_id);
        let heads = heads_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("FetchHeads reply");
        assert_eq!(heads, vec![cid_present]);

        // FetchHeads for an unknown rep_id returns empty.
        let unknown_rep = [0u8; 32];
        let empty_heads = net_a
            .fetch_heads(peer_b, unknown_rep)
            .recv_timeout(Duration::from_secs(5))
            .expect("FetchHeads reply for unknown group");
        assert!(empty_heads.is_empty());

        // FetchNode for a known CID returns Some.
        let node_rx = net_a.fetch_node(peer_b, rep_id, cid_present);
        let node = node_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("FetchNode reply");
        assert_eq!(node, Some(b"node-bytes-here".to_vec()));

        // FetchNode for an unknown CID returns None.
        let missing = net_a
            .fetch_node(peer_b, rep_id, cid_missing)
            .recv_timeout(Duration::from_secs(5))
            .expect("FetchNode reply for missing CID");
        assert_eq!(missing, None);

        net_a.join();
        net_b.join();
    }

    /// Network-level test: outbound `send_invoke` on A dispatches
    /// against an `InvokeDispatcher` installed on B, and the
    /// reply flows back through the request_response response
    /// slot to the original caller.
    #[test]
    fn cross_node_invoke_round_trips_reply() {
        struct RecordingDispatcher {
            seen: Arc<Mutex<Option<(u32, u32, Vec<u32>, Vec<u8>)>>>,
            reply: Vec<u8>,
        }

        impl InvokeDispatcher for RecordingDispatcher {
            fn dispatch(&self, from: u32, to: u32, chain: Vec<u32>, msg: Vec<u8>) -> Vec<u8> {
                *self.seen.lock().unwrap() =
                    Some((from, to, chain.clone(), msg));
                self.reply.clone()
            }
        }

        let kp_a = identity::Keypair::generate_ed25519();
        let kp_b = identity::Keypair::generate_ed25519();
        let prefix_a = 0xAAAA;
        let prefix_b = 0xBBBB;

        let listen_addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

        let net_a = Network::start(NetworkConfig {
            keypair: kp_a,
            local_prefix: prefix_a,
            listen: vec![listen_addr.clone()],
            bootstrap: vec![],
        });
        let a_listen = wait_for(
            || net_a.listen_addrs().into_iter().next(),
            Duration::from_secs(5),
        )
        .expect("net_a binds");
        let a_dial: Multiaddr = a_listen.with(libp2p::multiaddr::Protocol::P2p(net_a.peer_id()));

        let net_b = Network::start(NetworkConfig {
            keypair: kp_b,
            local_prefix: prefix_b,
            listen: vec![listen_addr],
            bootstrap: vec![a_dial],
        });

        // Install dispatcher on B before any invoke can race in.
        let seen = Arc::new(Mutex::new(None));
        net_b.set_invoke_dispatcher(Arc::new(RecordingDispatcher {
            seen: seen.clone(),
            reply: b"the answer".to_vec(),
        }));

        wait_for(
            || net_a.peer_for_prefix(prefix_b),
            Duration::from_secs(10),
        )
        .expect("Hello completes");

        let target_peer = net_a.peer_for_prefix(prefix_b).unwrap();
        let reply_rx = net_a.send_invoke(
            target_peer,
            0x00010002, // from
            0xBBBB0007, // to (B's local id 7)
            vec![0x00010002], // chain
            b"please reply".to_vec(),
        );

        let payload = reply_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("invoke reply");
        assert_eq!(payload, b"the answer");

        let seen = seen.lock().unwrap().clone().expect("dispatcher saw the call");
        assert_eq!(seen.0, 0x00010002);
        assert_eq!(seen.1, 0xBBBB0007);
        assert_eq!(seen.2, vec![0x00010002]);
        assert_eq!(seen.3, b"please reply");

        net_a.join();
        net_b.join();
    }

    /// Full path: `VosNode::invoke` on A finds no local route,
    /// falls through to the network, hits B's `LocalInvokeDispatcher`
    /// (installed by `attach_network`), which dispatches against
    /// B's invoke_routes table where a test responder lives.
    #[test]
    fn vosnode_invoke_falls_through_to_remote_node() {
        use crate::node::VosNode;

        let kp_a = identity::Keypair::generate_ed25519();
        let kp_b = identity::Keypair::generate_ed25519();
        let prefix_a = derive_node_prefix(&PeerId::from(kp_a.public()));
        let prefix_b = derive_node_prefix(&PeerId::from(kp_b.public()));

        let listen_addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

        let net_a = Network::start(NetworkConfig {
            keypair: kp_a,
            local_prefix: prefix_a,
            listen: vec![listen_addr.clone()],
            bootstrap: vec![],
        });
        let a_listen = wait_for(
            || net_a.listen_addrs().into_iter().next(),
            Duration::from_secs(5),
        )
        .expect("net_a binds");
        let a_dial: Multiaddr = a_listen.with(libp2p::multiaddr::Protocol::P2p(net_a.peer_id()));

        let net_b = Network::start(NetworkConfig {
            keypair: kp_b,
            local_prefix: prefix_b,
            listen: vec![listen_addr],
            bootstrap: vec![a_dial],
        });

        wait_for(
            || {
                if net_a.peer_for_prefix(prefix_b).is_some()
                    && net_b.peer_for_prefix(prefix_a).is_some()
                {
                    Some(())
                } else {
                    None
                }
            },
            Duration::from_secs(10),
        )
        .expect("Hello completes");

        // Build node B with a responder, then attach the network so
        // the LocalInvokeDispatcher sees the responder's route.
        let mut node_b = VosNode::with_prefix(prefix_b);
        let responder_id = node_b.install_invoke_responder(|msg| {
            // Echo with a marker so we can assert on the reply.
            let mut out = b"ack:".to_vec();
            out.extend_from_slice(&msg);
            out
        });
        node_b.attach_network(net_b);

        // Node A only needs the network — no local services.
        let mut node_a = VosNode::with_prefix(prefix_a);
        node_a.attach_network(net_a);

        // Cross-node invoke from outside the agent system.
        let reply = node_a
            .invoke_with_timeout(responder_id, b"ping".to_vec(), Duration::from_secs(5))
            .expect("cross-node invoke should resolve");
        assert_eq!(reply, b"ack:ping");

        // Sanity check: invoking a target with no local route AND no
        // remote owner returns None instead of hanging.
        let unknown = crate::abi::service::ServiceId::new(0xDEAD, 1);
        let nothing = node_a.invoke_with_timeout(unknown, b"".to_vec(), Duration::from_millis(500));
        assert!(nothing.is_none());

        // collect drops both nodes; their networks shut down with them.
        let _ = node_a.collect();
        let _ = node_b.collect();
    }

    /// End-to-end test: VosNode A pushes an envelope addressed to a
    /// service on node B. Path under test:
    ///
    /// ```text
    /// A.outbox -> A.route() -> A.network.send_tell()
    ///                       -> [libp2p /vos/0.1.0]
    ///                       -> B.swarm -> inbox -> bridge thread
    ///                       -> B.outbox -> B.route() -> inspector
    /// ```
    #[test]
    fn cross_node_tell_delivers_to_remote_inspector() {
        use crate::abi::service::ServiceId;
        use crate::node::{Envelope, VosNode};
        use std::sync::atomic::Ordering;

        let kp_a = identity::Keypair::generate_ed25519();
        let kp_b = identity::Keypair::generate_ed25519();
        let prefix_a = derive_node_prefix(&PeerId::from(kp_a.public()));
        let prefix_b = derive_node_prefix(&PeerId::from(kp_b.public()));
        assert_ne!(prefix_a, prefix_b, "test needs distinct prefixes");

        let listen_addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

        let net_a = Network::start(NetworkConfig {
            keypair: kp_a,
            local_prefix: prefix_a,
            listen: vec![listen_addr.clone()],
            bootstrap: vec![],
        });
        let a_listen = wait_for(
            || net_a.listen_addrs().into_iter().next(),
            Duration::from_secs(5),
        )
        .expect("net_a should bind");
        let a_dial: Multiaddr = a_listen.with(libp2p::multiaddr::Protocol::P2p(net_a.peer_id()));

        let net_b = Network::start(NetworkConfig {
            keypair: kp_b,
            local_prefix: prefix_b,
            listen: vec![listen_addr],
            bootstrap: vec![a_dial],
        });

        // Wait for the Hello round trip before attaching, so we can
        // still use the &Network handles for the prefix probe.
        wait_for(
            || {
                if net_a.peer_for_prefix(prefix_b).is_some()
                    && net_b.peer_for_prefix(prefix_a).is_some()
                {
                    Some(())
                } else {
                    None
                }
            },
            Duration::from_secs(10),
        )
        .expect("Hello should complete");

        // Attach networks to fresh nodes. Node B owns the inspector;
        // node A's inspector is unused (we only test A → B here).
        let mut node_a = VosNode::with_prefix(prefix_a);
        node_a.attach_network(net_a);
        let outbox_a = node_a.outbox_sender();
        let shutdown_a = node_a.shutdown_handle();

        let mut node_b = VosNode::with_prefix(prefix_b);
        let (inspector_id, inspector_rx) = node_b.install_inspector();
        node_b.attach_network(net_b);
        let shutdown_b = node_b.shutdown_handle();

        let join_a = std::thread::spawn(move || node_a.run_forever());
        let join_b = std::thread::spawn(move || node_b.run_forever());

        // From outside the agent system, inject an envelope addressed
        // to the inspector on B. A's routing loop sees a non-local
        // prefix and forwards over the network.
        let payload = b"cross-node hello".to_vec();
        outbox_a
            .send(Envelope {
                from: ServiceId::new(prefix_a, 0xFFFF),
                to: inspector_id,
                payload: payload.clone(),
            })
            .expect("outbox_a accepts envelope");

        let received = inspector_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("inspector on B should receive forwarded envelope");
        assert_eq!(received.from.0, ServiceId::new(prefix_a, 0xFFFF).0);
        assert_eq!(received.to, inspector_id);
        assert_eq!(received.payload, payload);

        // Stop both nodes (run_forever exits on shutdown flag).
        shutdown_a.store(true, Ordering::Relaxed);
        shutdown_b.store(true, Ordering::Relaxed);
        let _ = join_a.join();
        let _ = join_b.join();
    }

    #[test]
    fn identity_auto_persists_across_calls() {
        let dir = std::env::temp_dir().join(format!(
            "vos_net_id_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let k1 = load_or_generate_identity(Some("auto"), Some(&dir)).unwrap();
        let k2 = load_or_generate_identity(Some("auto"), Some(&dir)).unwrap();
        assert_eq!(
            PeerId::from(k1.public()),
            PeerId::from(k2.public()),
            "auto-identity should be stable across loads",
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn identity_explicit_path_loads_existing_key() {
        let dir = std::env::temp_dir().join(format!(
            "vos_net_explicit_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("custom.key");

        // Generate a key, save it manually, then load.
        let kp = identity::Keypair::generate_ed25519();
        let bytes = kp.to_protobuf_encoding().unwrap();
        std::fs::write(&path, &bytes).unwrap();

        let loaded = load_or_generate_identity(Some(path.to_str().unwrap()), None).unwrap();
        assert_eq!(PeerId::from(kp.public()), PeerId::from(loaded.public()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Phase-2 boundary for Raft: the wire frames + libp2p plumbing
    /// route an outbound `AppendEntries` / `RequestVote` to the
    /// remote peer, the stub handler observes the call, and the
    /// canned response makes it back through the caller's channel.
    /// No election or replication logic is exercised — that's
    /// phase 3+ — but every wire bit is.
    #[test]
    fn raft_rpcs_route_through_libp2p_to_handler_and_back() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Mutex as StdMutex;

        // Stub handler: record the inbound RPC params and reply
        // with deterministic canned values so the caller's
        // assertions can pin down both directions.
        struct StubHandler {
            append_calls: StdMutex<Vec<(u16, u64, u64, u64, u64, usize)>>,
            vote_calls: StdMutex<Vec<(u16, u64, u64, u64)>>,
            term: AtomicU64,
        }
        impl StubHandler {
            fn new(initial_term: u64) -> Self {
                Self {
                    append_calls: StdMutex::new(Vec::new()),
                    vote_calls: StdMutex::new(Vec::new()),
                    term: AtomicU64::new(initial_term),
                }
            }
        }
        impl RaftRpcHandler for StubHandler {
            fn append_entries(
                &self,
                _replication_id: &[u8; 32],
                from_prefix: u16,
                term: u64,
                prev_log_index: u64,
                prev_log_term: u64,
                leader_commit: u64,
                entries: Vec<RaftEntry>,
            ) -> RaftAppendResult {
                self.append_calls.lock().unwrap().push((
                    from_prefix,
                    term,
                    prev_log_index,
                    prev_log_term,
                    leader_commit,
                    entries.len(),
                ));
                let local_term = self.term.load(Ordering::Relaxed);
                RaftAppendResult {
                    term: local_term,
                    success: term >= local_term,
                    match_index: prev_log_index + entries.len() as u64,
                }
            }
            fn request_vote(
                &self,
                _replication_id: &[u8; 32],
                from_prefix: u16,
                term: u64,
                last_log_index: u64,
                last_log_term: u64,
            ) -> RaftVoteResult {
                self.vote_calls.lock().unwrap().push((
                    from_prefix,
                    term,
                    last_log_index,
                    last_log_term,
                ));
                let local_term = self.term.load(Ordering::Relaxed);
                RaftVoteResult {
                    term: local_term,
                    vote_granted: term >= local_term,
                }
            }
        }

        let kp_a = identity::Keypair::generate_ed25519();
        let kp_b = identity::Keypair::generate_ed25519();
        let prefix_a = 0xAAAA;
        let prefix_b = 0xBBBB;
        let listen_addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

        let net_a = Network::start(NetworkConfig {
            keypair: kp_a,
            local_prefix: prefix_a,
            listen: vec![listen_addr.clone()],
            bootstrap: vec![],
        });
        let a_addr = wait_for(
            || net_a.listen_addrs().into_iter().next(),
            Duration::from_secs(5),
        ).expect("net_a binds");
        let a_dial: Multiaddr = a_addr.with(libp2p::multiaddr::Protocol::P2p(net_a.peer_id()));

        let net_b = Network::start(NetworkConfig {
            keypair: kp_b,
            local_prefix: prefix_b,
            listen: vec![listen_addr],
            bootstrap: vec![a_dial],
        });

        // Install the stub on B — A is the leader-side caller.
        let rep_id = [0xC0u8; 32];
        let handler = Arc::new(StubHandler::new(7));
        net_b.register_raft_handler(rep_id, handler.clone());

        // Wait for the Hello handshake so A has a PeerId for B.
        wait_for(|| {
            (net_a.peer_for_prefix(prefix_b).is_some()
                && net_b.peer_for_prefix(prefix_a).is_some()).then_some(())
        }, Duration::from_secs(10))
        .expect("Hello completes");
        let target_b = net_a.peer_for_prefix(prefix_b).unwrap();

        // ── AppendEntries: send two entries from term 8. ──────
        let entries = vec![
            RaftEntry::data(8, b"first".to_vec()),
            RaftEntry::data(8, b"second".to_vec()),
        ];
        let rx = net_a.send_raft_append(
            target_b, rep_id,
            8,                  // term
            prefix_a,           // leader_prefix
            10,                 // prev_log_index
            7,                  // prev_log_term
            10,                 // leader_commit
            entries,
        );
        let resp = rx.recv_timeout(Duration::from_secs(5))
            .expect("AppendEntries response");
        assert_eq!(resp.term, 7, "stub returned its own term");
        assert!(resp.success, "term=8 >= local 7 → success");
        assert_eq!(resp.match_index, 12, "prev_log_index + entries.len()");

        // ── Stub recorded the inbound call. ───────────────────
        let calls = handler.append_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0],
            (prefix_a, 8u64, 10u64, 7u64, 10u64, 2usize),
            "from_prefix, term, prev_idx, prev_term, leader_commit, entries.len",
        );
        drop(calls);

        // ── RequestVote: term 9 with up-to-date log. ──────────
        let rx = net_a.send_raft_vote(
            target_b, rep_id,
            9,                  // term
            prefix_a,           // candidate_prefix
            12,                 // last_log_index
            8,                  // last_log_term
        );
        let resp = rx.recv_timeout(Duration::from_secs(5))
            .expect("RequestVote response");
        assert_eq!(resp.term, 7);
        assert!(resp.vote_granted, "term=9 >= local 7 → granted");

        let calls = handler.vote_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], (prefix_a, 9u64, 12u64, 8u64));
        drop(calls);

        // ── No-handler fallback: a peer with no handler installed
        // returns success=false / vote_granted=false (not a hang). ──
        // Reverse the direction: B asks A, but A has no handler.
        let target_a = net_b.peer_for_prefix(prefix_a).unwrap();
        let rx = net_b.send_raft_append(
            target_a, rep_id, 1, prefix_b, 0, 0, 0, vec![],
        );
        let resp = rx.recv_timeout(Duration::from_secs(5))
            .expect("no-handler response");
        assert!(!resp.success, "no handler installed → success=false");
        assert_eq!(resp.match_index, 0);

        net_a.join();
        net_b.join();
    }

    /// Phase-3.2 boundary: three networked nodes spin up Raft
    /// workers configured for the same cluster, run for a short
    /// while, and exactly one becomes Leader. No replication,
    /// no log writes — just election. The leader's term must
    /// match across all three replicas; the two losers stay
    /// Follower and have `voted_for == leader`.
    #[test]
    fn three_node_cluster_elects_a_leader() {
        use crate::raft::{RaftWorker, Role, WorkerConfig};
        use std::time::Instant as StdInstant;

        let kp_a = identity::Keypair::generate_ed25519();
        let kp_b = identity::Keypair::generate_ed25519();
        let kp_c = identity::Keypair::generate_ed25519();
        let prefix_a = derive_node_prefix(&PeerId::from(kp_a.public()));
        let prefix_b = derive_node_prefix(&PeerId::from(kp_b.public()));
        let prefix_c = derive_node_prefix(&PeerId::from(kp_c.public()));
        // Skip if any two prefixes happen to collide on the
        // 16-bit truncation (vanishingly rare in practice but
        // possible with random keypairs).
        if prefix_a == prefix_b || prefix_a == prefix_c || prefix_b == prefix_c {
            eprintln!("SKIP: prefix collision; rerun");
            return;
        }
        let listen_addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

        let net_a = Arc::new(Network::start(NetworkConfig {
            keypair: kp_a, local_prefix: prefix_a,
            listen: vec![listen_addr.clone()], bootstrap: vec![],
        }));
        let a_addr = wait_for(
            || net_a.listen_addrs().into_iter().next(),
            Duration::from_secs(5),
        ).expect("net_a binds");
        let a_dial: Multiaddr = a_addr.with(libp2p::multiaddr::Protocol::P2p(net_a.peer_id()));

        let net_b = Arc::new(Network::start(NetworkConfig {
            keypair: kp_b, local_prefix: prefix_b,
            listen: vec![listen_addr.clone()], bootstrap: vec![a_dial.clone()],
        }));
        // Wait for B's listen addr so C can bootstrap to both A
        // and B — without an explicit dial between B and C the
        // mesh wouldn't form within the test deadline.
        let b_addr = wait_for(
            || net_b.listen_addrs().into_iter().next(),
            Duration::from_secs(5),
        ).expect("net_b binds");
        let b_dial: Multiaddr = b_addr.with(libp2p::multiaddr::Protocol::P2p(net_b.peer_id()));

        let net_c = Arc::new(Network::start(NetworkConfig {
            keypair: kp_c, local_prefix: prefix_c,
            listen: vec![listen_addr], bootstrap: vec![a_dial, b_dial],
        }));

        // Wait for the Hello triangle to close.
        wait_for(|| {
            let ab = net_a.peer_for_prefix(prefix_b).is_some()
                  && net_b.peer_for_prefix(prefix_a).is_some();
            let ac = net_a.peer_for_prefix(prefix_c).is_some()
                  && net_c.peer_for_prefix(prefix_a).is_some();
            let bc = net_b.peer_for_prefix(prefix_c).is_some()
                  && net_c.peer_for_prefix(prefix_b).is_some();
            (ab && ac && bc).then_some(())
        }, Duration::from_secs(15))
        .expect("3-node Hello mesh forms");

        // Each node gets its own redb file + worker.
        let dir = std::env::temp_dir().join(format!(
            "vos_raft_election_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mk_worker = |me, network: Arc<Network>, db_name: &str| {
            let db = Arc::new(redb::Database::create(dir.join(db_name)).unwrap());
            RaftWorker::spawn(
                db,
                WorkerConfig {
                    me,
                    members: vec![prefix_a, prefix_b, prefix_c],
                    replication_id: [0xC1; 32],
                    // Short window so the test settles in well
                    // under a second. The randomization scatters
                    // peer timeouts so they don't all become
                    // candidates at once.
                    election_timeout_ms: (50, 150),
                    // Heartbeat fires comfortably inside the
                    // election window so followers' timers are
                    // reset before they can challenge.
                    heartbeat_interval_ms: 20,
                },
                Some(network),
                None,
            )
        };
        let w_a = mk_worker(prefix_a, net_a.clone(), "a.redb");
        let w_b = mk_worker(prefix_b, net_b.clone(), "b.redb");
        let w_c = mk_worker(prefix_c, net_c.clone(), "c.redb");
        let rep_id = [0xC1u8; 32];
        net_a.register_raft_handler(rep_id, Arc::new(w_a.handler()));
        net_b.register_raft_handler(rep_id, Arc::new(w_b.handler()));
        net_c.register_raft_handler(rep_id, Arc::new(w_c.handler()));

        // Phase 3.3: heartbeats keep followers' timers reset, so
        // leadership is *stable* — once a Leader emerges it stays
        // Leader and the term doesn't drift. Wait for a Leader,
        // then sample for several heartbeat intervals and assert
        // role + term hold.
        let until = StdInstant::now() + Duration::from_secs(5);
        let mut observed: Option<(u16, u64)> = None;
        loop {
            let snaps = [
                (prefix_a, w_a.handler().snapshot()),
                (prefix_b, w_b.handler().snapshot()),
                (prefix_c, w_c.handler().snapshot()),
            ];
            for (p, s) in &snaps {
                if let Some(snap) = s {
                    if snap.role == Role::Leader && snap.current_term >= 1 {
                        observed = Some((*p, snap.current_term));
                        assert_eq!(snap.voted_for, Some(*p),
                            "a Leader voted for itself this term");
                        break;
                    }
                }
            }
            if observed.is_some() { break; }
            if StdInstant::now() >= until {
                panic!(
                    "no Leader observed within deadline; \
                     last snapshots: A={:?}, B={:?}, C={:?}",
                    snaps[0].1, snaps[1].1, snaps[2].1,
                );
            }
            std::thread::sleep(Duration::from_millis(15));
        }
        let (leader_prefix, leader_term) = observed.unwrap();
        assert!([prefix_a, prefix_b, prefix_c].contains(&leader_prefix));
        assert!(leader_term >= 1);

        // ── Steady-state probe (phase 3.3) ────────────────────
        // Sample for ~10 heartbeat intervals: the same node stays
        // Leader, the term doesn't bump, and the followers stay
        // Followers with their `voted_for` pointing at the leader.
        std::thread::sleep(Duration::from_millis(200));
        let leader_handle = match leader_prefix {
            p if p == prefix_a => w_a.handler(),
            p if p == prefix_b => w_b.handler(),
            _ => w_c.handler(),
        };
        let snap_leader = leader_handle.snapshot().expect("leader alive");
        assert_eq!(snap_leader.role, Role::Leader,
            "phase 3.3: heartbeats must keep the leader from getting demoted; \
             snap = {snap_leader:?}");
        assert_eq!(snap_leader.current_term, leader_term,
            "phase 3.3: term must not drift while the leader is heartbeating");

        let other_snaps: Vec<_> = [(prefix_a, w_a.handler()),
                                   (prefix_b, w_b.handler()),
                                   (prefix_c, w_c.handler())]
            .into_iter()
            .filter(|(p, _)| *p != leader_prefix)
            .map(|(p, h)| (p, h.snapshot().expect("follower alive")))
            .collect();
        for (p, snap) in &other_snaps {
            assert_eq!(
                snap.role, Role::Follower,
                "follower at {p:#06x} must not have re-elected; snap = {snap:?}",
            );
            assert_eq!(
                snap.current_term, leader_term,
                "follower's term must match the leader's after the heartbeat round",
            );
        }

        // Cleanly stop the workers before joining the networks
        // so any in-flight outbound vote helpers exit.
        w_a.shutdown();
        w_b.shutdown();
        w_c.shutdown();
        match Arc::try_unwrap(net_a) { Ok(n) => n.join(), Err(_) => {} }
        match Arc::try_unwrap(net_b) { Ok(n) => n.join(), Err(_) => {} }
        match Arc::try_unwrap(net_c) { Ok(n) => n.join(), Err(_) => {} }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Phase-4.3 boundary: 3-node cluster, elect a leader, propose
    /// three entries via the leader's `WorkerHandle::propose`, and
    /// wait for both followers to replicate them. Direct redb
    /// introspection asserts every replica has four rows in
    /// `raft_log` (the leader-promotion no-op at index 1 plus the
    /// three application proposes at indices 2..=4) and
    /// `commit_index == 4`.
    #[test]
    fn three_node_cluster_replicates_proposed_entries() {
        use crate::raft::{RaftMeta, RaftWorker, Role, WorkerConfig, RAFT_LOG};
        use redb::ReadableTableMetadata;
        use std::time::Instant as StdInstant;

        let kp_a = identity::Keypair::generate_ed25519();
        let kp_b = identity::Keypair::generate_ed25519();
        let kp_c = identity::Keypair::generate_ed25519();
        let prefix_a = derive_node_prefix(&PeerId::from(kp_a.public()));
        let prefix_b = derive_node_prefix(&PeerId::from(kp_b.public()));
        let prefix_c = derive_node_prefix(&PeerId::from(kp_c.public()));
        if prefix_a == prefix_b || prefix_a == prefix_c || prefix_b == prefix_c {
            eprintln!("SKIP: prefix collision; rerun");
            return;
        }
        let listen_addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

        let net_a = Arc::new(Network::start(NetworkConfig {
            keypair: kp_a, local_prefix: prefix_a,
            listen: vec![listen_addr.clone()], bootstrap: vec![],
        }));
        let a_addr = wait_for(
            || net_a.listen_addrs().into_iter().next(),
            Duration::from_secs(5),
        ).expect("net_a binds");
        let a_dial: Multiaddr = a_addr.with(libp2p::multiaddr::Protocol::P2p(net_a.peer_id()));

        let net_b = Arc::new(Network::start(NetworkConfig {
            keypair: kp_b, local_prefix: prefix_b,
            listen: vec![listen_addr.clone()], bootstrap: vec![a_dial.clone()],
        }));
        let b_addr = wait_for(
            || net_b.listen_addrs().into_iter().next(),
            Duration::from_secs(5),
        ).expect("net_b binds");
        let b_dial: Multiaddr = b_addr.with(libp2p::multiaddr::Protocol::P2p(net_b.peer_id()));

        let net_c = Arc::new(Network::start(NetworkConfig {
            keypair: kp_c, local_prefix: prefix_c,
            listen: vec![listen_addr], bootstrap: vec![a_dial, b_dial],
        }));

        wait_for(|| {
            let ab = net_a.peer_for_prefix(prefix_b).is_some()
                  && net_b.peer_for_prefix(prefix_a).is_some();
            let ac = net_a.peer_for_prefix(prefix_c).is_some()
                  && net_c.peer_for_prefix(prefix_a).is_some();
            let bc = net_b.peer_for_prefix(prefix_c).is_some()
                  && net_c.peer_for_prefix(prefix_b).is_some();
            (ab && ac && bc).then_some(())
        }, Duration::from_secs(15))
        .expect("3-node Hello mesh forms");

        let dir = std::env::temp_dir().join(format!(
            "vos_raft_replicate_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mk_worker = |me, network: Arc<Network>, db_name: &str| {
            let path = dir.join(db_name);
            let db = Arc::new(redb::Database::create(&path).unwrap());
            (
                path,
                RaftWorker::spawn(
                    db,
                    WorkerConfig {
                        me,
                        members: vec![prefix_a, prefix_b, prefix_c],
                        replication_id: [0xC2; 32],
                        election_timeout_ms: (50, 150),
                        heartbeat_interval_ms: 20,
                    },
                    Some(network),
                    None,
                ),
            )
        };
        let (path_a, w_a) = mk_worker(prefix_a, net_a.clone(), "a.redb");
        let (path_b, w_b) = mk_worker(prefix_b, net_b.clone(), "b.redb");
        let (path_c, w_c) = mk_worker(prefix_c, net_c.clone(), "c.redb");
        let rep_id = [0xC2u8; 32];
        net_a.register_raft_handler(rep_id, Arc::new(w_a.handler()));
        net_b.register_raft_handler(rep_id, Arc::new(w_b.handler()));
        net_c.register_raft_handler(rep_id, Arc::new(w_c.handler()));

        // ── Wait for a leader. ────────────────────────────────
        let until = StdInstant::now() + Duration::from_secs(5);
        let mut leader: Option<u16> = None;
        loop {
            for (p, h) in [
                (prefix_a, w_a.handler()),
                (prefix_b, w_b.handler()),
                (prefix_c, w_c.handler()),
            ] {
                if let Some(snap) = h.snapshot() {
                    if snap.role == Role::Leader {
                        leader = Some(p);
                        break;
                    }
                }
            }
            if leader.is_some() { break; }
            assert!(StdInstant::now() < until, "no leader within deadline");
            std::thread::sleep(Duration::from_millis(15));
        }
        let leader_prefix = leader.unwrap();
        let leader_handle = match leader_prefix {
            p if p == prefix_a => w_a.handler(),
            p if p == prefix_b => w_b.handler(),
            _ => w_c.handler(),
        };

        // ── Propose three entries on the leader. ──────────────
        let payloads = [b"alpha".to_vec(), b"beta".to_vec(), b"gamma".to_vec()];
        for p in &payloads {
            let idx = leader_handle.propose(p.clone()).expect("propose");
            assert!(idx >= 1);
        }

        // ── Wait for all replicas to commit_index ≥ 4. ────────
        // The leader appends a no-op entry on promotion (Ongaro
        // §6.4) at index 1; the three application proposes land
        // at indices 2..=4. Quorum-commit fires when followers'
        // match_index reaches 4 → leader's commit_index = 4 →
        // next heartbeat propagates leader_commit to followers.
        // Probe commit_index via the snapshot — the worker holds
        // the exclusive redb file lock, so direct introspection
        // is deferred until shutdown below.
        let until = StdInstant::now() + Duration::from_secs(10);
        loop {
            let snaps = [
                (prefix_a, w_a.handler().snapshot()),
                (prefix_b, w_b.handler().snapshot()),
                (prefix_c, w_c.handler().snapshot()),
            ];
            let all_committed = snaps.iter().all(|(_, s)| {
                s.as_ref().is_some_and(|x| x.commit_index >= 4)
            });
            if all_committed { break; }
            if StdInstant::now() >= until {
                panic!(
                    "all replicas did not reach commit_index ≥ 4 within \
                     deadline; snaps: {snaps:?}",
                );
            }
            std::thread::sleep(Duration::from_millis(25));
        }

        // ── Probe each replica's redb directly. ──────────────
        // We need the workers stopped before opening the redb
        // files (they hold the exclusive file lock). Shut them
        // down + collect, then read.
        w_a.shutdown();
        w_b.shutdown();
        w_c.shutdown();

        for (label, path) in [("A", &path_a), ("B", &path_b), ("C", &path_c)] {
            let db = redb::Database::create(path).expect("reopen");
            let txn = db.begin_read().expect("read txn");
            let log_table = txn.open_table(RAFT_LOG).expect("raft_log");
            let n_rows = log_table.len().expect("len");
            assert_eq!(
                n_rows, 4,
                "replica {label} should have exactly 4 raft_log rows \
                 (leader-promotion no-op + 3 application proposes); \
                 got {n_rows}",
            );
            let meta = RaftMeta::load(&db).expect("meta");
            // The leader appends a no-op on promotion (idx 1) and
            // the three application proposes land at idx 2..=4.
            // commit_index advances to 4 once a majority matches
            // the leader; followers see it on the next heartbeat.
            assert_eq!(
                meta.commit_index, 4,
                "replica {label} commit_index should advance to 4",
            );
            // `last_applied` is now the host's responsibility
            // (vos_raft::Meta no longer tracks it). On the leader
            // it's bumped by `RaftCommit::commit_with_log`'s state
            // write; followers' `last_applied` only advances when
            // their agent thread runs the apply path. This test
            // probes redb directly without going through RaftCommit
            // on the followers, so we only check `commit_index`
            // here — the apply-tracking integration test in
            // `tests/elf_integration.rs` covers the host-level
            // last_applied advance end-to-end.
        }

        match Arc::try_unwrap(net_a) { Ok(n) => n.join(), Err(_) => {} }
        match Arc::try_unwrap(net_b) { Ok(n) => n.join(), Err(_) => {} }
        match Arc::try_unwrap(net_c) { Ok(n) => n.join(), Err(_) => {} }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
