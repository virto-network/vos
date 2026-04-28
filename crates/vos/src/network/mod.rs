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

pub use wire::{Frame, FrameError, MAX_FRAME_BYTES};

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{mpsc as std_mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use libp2p::futures::StreamExt;
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

/// Map: peer's `node_prefix` → its `PeerId`. Populated as Hello
/// frames flow in. Cheap to clone — owned by both the swarm
/// thread and any [`Network`] callers that want to look up a
/// peer by prefix.
type PrefixMap = Arc<Mutex<HashMap<u16, PeerId>>>;

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
    Shutdown,
}

/// Outbound request kinds tracked while we wait for the reply.
enum OutboundReply {
    Invoke(std_mpsc::Sender<Vec<u8>>),
    Heads(std_mpsc::Sender<Vec<[u8; 32]>>),
    Node(std_mpsc::Sender<Option<Vec<u8>>>),
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
        let (cmd_tx, cmd_rx) = async_mpsc::unbounded_channel();
        let (inbox_tx, inbox_rx) = std_mpsc::channel();

        let prefix_map_for_thread = prefix_map.clone();
        let listen_addrs_for_thread = listen_addrs.clone();
        let invoke_dispatcher_for_thread = invoke_dispatcher.clone();
        let sync_provider_for_thread = sync_provider.clone();
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

    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                handle_swarm_event(
                    &mut swarm, event, local_prefix,
                    &prefix_map, &listen_addrs, &inbox_tx,
                    &mut outbound_replies,
                    &invoke_dispatcher,
                    &sync_provider,
                    &response_tx,
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
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(VosBehaviour {
                mdns,
                ping,
                identify,
                req_resp,
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
    response_tx: &async_mpsc::UnboundedSender<(request_response::ResponseChannel<Frame>, Frame)>,
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
                outbound_replies, invoke_dispatcher, sync_provider, response_tx,
            );
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
        let arc_a = node_a.install_test_replica(rep_id, &path_a);
        let mut node_b = VosNode::with_prefix(prefix_b);
        let _arc_b = node_b.install_test_replica(rep_id, &path_b);

        // Drive A: two CRDT commits.
        let log1 = EffectLog::for_msg(b"first".to_vec());
        let log2 = EffectLog::for_msg(b"second".to_vec());
        {
            let mut cc_a = CrdtCommit::from_db_arc(arc_a.clone());
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
                let cc = CrdtCommit::from_db_arc(_arc_b.clone());
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
        let cc_a = CrdtCommit::from_db_arc(arc_a);
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
        let _arc_b = node_b.install_test_replica(rep_id, &db_path_b);

        // Drop _arc_b out of scope so CrdtCommit::from_db_arc gets
        // *the same* Arc through the map (we keep one in the map).
        // Drive a couple of CRDT commits through a second Arc clone.
        let arc_b_for_writes = node_b
            .crdt_replicas
            .lock()
            .unwrap()
            .get(&rep_id)
            .cloned()
            .unwrap();
        let mut cc = CrdtCommit::from_db_arc(arc_b_for_writes);
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
}
