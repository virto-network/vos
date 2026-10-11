//! What arrives from the space's other nodes: each frame checked, then
//! routed to its agent's group, or handled by the node itself (the
//! directory, and blobs).
//!
//! The directory: where each agent runs. The node that creates an agent
//! sends its record and first placement to every node of the space, and
//! the agent's leader sends each new placement as its replicas change,
//! again every second until each node acknowledges holding it durably. A
//! node keeps the newest placement by its order (the announcing leader's
//! term, then the configuration's index), and a record that differs from
//! the one held for its agent is refused, never written over.

use std::sync::Arc;
use std::time::{Duration, Instant};

use smol::future::FutureExt;
use vos_net::{Arrivals, Class, Incoming};
use vos_wire::Encode;
use vos_wire::ids::AgentId;
use vos_wire::peer::{CreationRecord, NodeNumber, PeerMessage, Placement};

use crate::group::Input;
use crate::node::{Inner, Order};
use crate::peer;
use crate::storage::Change;
use crate::store::BlobRef;

/// How often unacknowledged records are sent again.
const RESEND: Duration = Duration::from_secs(1);
/// How long the operator's creation waits for a majority of the replicas.
const MAJORITY: Duration = Duration::from_secs(30);
/// How long a blob being served waits for room in its peer's queue.
const BLOB_ROOM: Duration = Duration::from_secs(5);

/// Take arrivals until the network closes.
pub(crate) async fn dispatch(inner: Arc<Inner>, arrivals: Arrivals) {
    while let Some((class, incoming)) = take(&arrivals).await {
        inner.arrive(class, incoming).await;
    }
}

/// The next arrival: consensus before anything else. Liveness frames go
/// to the pair heartbeat's own thread.
async fn take(arrivals: &Arrivals) -> Option<(Class, Incoming)> {
    if let Ok(incoming) = arrivals.consensus.try_recv() {
        return Some((Class::Consensus, incoming));
    }
    let on = |class: Class, queue: &smol::channel::Receiver<Incoming>| {
        let queue = queue.clone();
        async move { queue.recv().await.ok().map(|incoming| (class, incoming)) }
    };
    on(Class::Consensus, &arrivals.consensus)
        .or(on(Class::Requests, &arrivals.requests))
        .or(on(Class::Bulk, &arrivals.bulk))
        .await
}

/// Send unacknowledged placements again until each node holds them.
pub(crate) async fn resend_records(inner: Arc<Inner>) {
    loop {
        smol::Timer::after(RESEND).await;
        // Every node runs this, a space of one too.
        inner.halt_if_store_failed();
        let pending: Vec<(AgentId, Order, Vec<NodeNumber>)> = inner
            .unacknowledged
            .lock()
            .expect("the unacknowledged records")
            .iter()
            .map(|(agent, (order, nodes))| (*agent, *order, nodes.iter().copied().collect()))
            .collect();
        for (agent, announced, nodes) in pending {
            let known = inner
                .directory
                .lock()
                .expect("the directory")
                .get(&agent)
                .cloned();
            // A placement held since from elsewhere is its sender's to
            // announce: this node may not even be one that may send it.
            if known
                .as_ref()
                .is_some_and(|known| known.placement.order() != announced)
            {
                let mut unacknowledged = inner
                    .unacknowledged
                    .lock()
                    .expect("the unacknowledged records");
                if unacknowledged
                    .get(&agent)
                    .is_some_and(|(order, _)| *order == announced)
                {
                    unacknowledged.remove(&agent);
                }
                continue;
            }
            if let Some(known) = known {
                let message = PeerMessage::Directory {
                    record: known.record,
                    placement: known.placement,
                };
                for node in nodes {
                    inner.send(node, Class::Requests, &message);
                }
            }
        }
    }
}

impl Inner {
    pub(crate) fn send(&self, to: NodeNumber, class: Class, message: &PeerMessage) {
        if let Some(network) = &self.network {
            let _ = network.send(to, class, peer::stream(message), message.encode());
        }
    }

    /// Give `agent`'s group `input`: dropped, and counted, when no group
    /// here runs it or its inbox is full; the sender sends again.
    fn to_group(&self, agent: AgentId, input: Input) {
        let routed = self
            .run(agent)
            .is_some_and(|run| run.inbox.try_send(input).is_ok());
        if !routed {
            self.drops.count(peer::Refusal::Unrouted);
        }
    }

    /// The leader `agent`'s replica here follows, and its term.
    fn followed(&self, agent: AgentId) -> Option<(NodeNumber, u64)> {
        let state = self.run(agent)?.shared.state();
        Some((state.leader?, state.term))
    }

    /// Check an arrival and route it. Only Raft routing runs inline: a
    /// blob (hashed) and a creation record (committed) run in tasks of
    /// their own, so no group's consensus waits behind them.
    async fn arrive(self: &Arc<Self>, class: Class, incoming: Incoming) {
        let Incoming {
            from,
            stream,
            frame,
        } = incoming;
        let message = match peer::decode(&frame) {
            Ok(message) => message,
            Err(refusal) => {
                self.drops.count(refusal);
                return;
            }
        };
        let space = self
            .space
            .as_ref()
            .map(|space| space.numbers())
            .unwrap_or_default();
        if matches!(
            message,
            PeerMessage::Blob { .. } | PeerMessage::Directory { .. }
        ) {
            let inner = Arc::clone(self);
            self.spawn(async move {
                let checked = inner
                    .offload(move || {
                        let checked =
                            peer::check(&space, from, (class, stream), &message, |_| None);
                        (checked, message)
                    })
                    .await;
                let Some((checked, message)) = checked else {
                    return;
                };
                if let Err(refusal) = checked {
                    inner.drops.count(refusal);
                    return;
                }
                match message {
                    PeerMessage::Blob { hash, bytes } => inner.take_blob(hash, bytes).await,
                    PeerMessage::Directory { record, placement } => {
                        inner.on_directory(from, record, placement).await
                    }
                    _ => unreachable!("only blobs and records are handled here"),
                }
            });
            return;
        }
        let checked = peer::check(&space, from, (class, stream), &message, |agent| {
            self.followed(agent)
        });
        if let Err(refusal) = checked {
            self.drops.count(refusal);
            tracing::debug!(from, ?refusal, "a peer's message was dropped");
            return;
        }
        match message {
            PeerMessage::Raft { agent, message } => {
                let routed = self.run(agent).is_some_and(|run| {
                    run.inbox
                        .try_send(Input::Raft {
                            from,
                            message: peer::from_wire(message),
                        })
                        .is_ok()
                });
                if !routed {
                    // No group here, or its inbox is full: Raft sends again.
                    self.drops.count(peer::Refusal::Unrouted);
                }
            }
            PeerMessage::BlobRequest { agent, hashes } => self.serve_blobs(from, agent, hashes),
            PeerMessage::DirectoryAck { agent, order, runs } => {
                self.on_ack(from, agent, order, runs)
            }
            // A task of its own runs the call: the dispatcher never waits.
            PeerMessage::Forward { agent, token, call } => {
                self.on_forward(from, agent, token, call)
            }
            PeerMessage::Forwarded {
                agent,
                token,
                answer,
            } => self.on_forwarded(from, agent, token, answer),
            // A task of its own confirms the leadership: the dispatcher
            // never waits.
            PeerMessage::ReadIndex { agent, token } => self.on_read_index(from, agent, token),
            PeerMessage::ReadIndexAnswer {
                agent,
                token,
                index,
            } => self.on_read_index_answer(from, agent, token, index),
            PeerMessage::Deliver {
                to,
                message,
                relayed,
            } => self.on_deliver(from, to, message, relayed),
            PeerMessage::Acknowledge {
                sender,
                receiver,
                sequence,
                relayed,
            } => self.on_acknowledge(from, sender, receiver, sequence, relayed),
            PeerMessage::Blob { .. } | PeerMessage::Directory { .. } => {
                unreachable!("blobs and records are handled in tasks")
            }
            PeerMessage::SnapshotChunk(chunk) => {
                let agent = chunk.agent;
                self.to_group(agent, Input::Chunk { from, chunk });
            }
            PeerMessage::SnapshotAck(ack) => {
                let agent = ack.agent;
                self.to_group(agent, Input::ChunkAck { from, ack });
            }
            // Taken on the pair heartbeat's own thread; none arrives here.
            PeerMessage::Liveness { .. } => {}
        }
    }

    /// Send `from` the blobs it asked for that this node holds, if it
    /// replicates `agent`.
    fn serve_blobs(self: &Arc<Self>, from: NodeNumber, agent: AgentId, hashes: Vec<[u8; 32]>) {
        let replica = self
            .placement(agent)
            .is_some_and(|placement| placement.admits(from));
        if !replica {
            tracing::debug!(
                from,
                agent = agent.0,
                "a blob request from a node not replicating its agent"
            );
            return;
        }
        if !self.hooks.serve_blob() {
            return;
        }
        let inner = Arc::clone(self);
        self.spawn(async move {
            // One at a time, each once the peer's queue has room for it:
            // a blob is read only to be sent.
            for hash in hashes {
                if let Some(network) = &inner.network {
                    let room = async {
                        network.ready(from, Class::Bulk).await;
                        true
                    };
                    let late = async {
                        smol::Timer::after(BLOB_ROOM).await;
                        false
                    };
                    if !room.or(late).await {
                        return;
                    }
                }
                let blobs = inner.blobs.clone();
                let read = inner.offload(move || blobs.get(&hash)).await;
                if let Some(Ok(Some(bytes))) = read {
                    // Refused, it is dropped: the replica asks again.
                    inner.send(from, Class::Bulk, &PeerMessage::Blob { hash, bytes });
                }
            }
        });
    }

    /// Store a blob a group asked for, and tell the groups waiting on it.
    /// One nobody asked for is dropped.
    async fn take_blob(&self, hash: [u8; 32], bytes: Vec<u8>) {
        // A store that failed takes nothing more.
        if !self.is_wanted(&hash) || self.storage.failed() {
            return;
        }
        let blob = BlobRef {
            hash,
            len: bytes.len() as u64,
        };
        match self.blobs.put(blob, Arc::new(bytes)).await {
            Ok(()) => self.arrived(&hash),
            Err(error) => tracing::warn!("a blob from a peer was not stored: {error}"),
        }
    }

    /// Keep a placement newer than the one held, with its record, durably,
    /// act on it, then acknowledge it, saying whether this node could run
    /// the agent's program.
    async fn on_directory(
        self: &Arc<Self>,
        from: NodeNumber,
        record: CreationRecord,
        placement: Placement,
    ) {
        // A store that failed takes nothing more, and its node does not
        // acknowledge: the sender's resends are dropped quietly.
        if self.storage.failed() {
            return;
        }
        let agent = record.agent;
        let order = placement.order();
        let recording = self.recording.lock().await;
        let known = self
            .directory
            .lock()
            .expect("the directory")
            .get(&agent)
            .cloned();
        if known.as_ref().is_some_and(|known| known.record != record) {
            tracing::error!(
                from,
                agent = agent.0,
                "a record differs from the one held for its agent; refused"
            );
            return;
        }
        if known
            .as_ref()
            .is_none_or(|known| placement.supersedes(&known.placement))
        {
            let mut changes = vec![Change::Placement {
                agent,
                placement: placement.clone(),
            }];
            if known.is_none() {
                changes.insert(0, Change::Agent(record.clone()));
            }
            if let Err(error) = self.commit(changes).await {
                tracing::error!(agent = agent.0, "a placement was not stored: {error}");
                return;
            }
            self.learn(record.clone(), placement);
        }
        drop(recording);
        self.send(
            from,
            Class::Requests,
            &PeerMessage::DirectoryAck {
                agent,
                order,
                runs: record.program == self.program_hash,
            },
        );
    }

    fn on_ack(&self, from: NodeNumber, agent: AgentId, order: Order, runs: bool) {
        let mut unacknowledged = self
            .unacknowledged
            .lock()
            .expect("the unacknowledged records");
        if let Some((announced, nodes)) = unacknowledged.get_mut(&agent)
            && order >= *announced
        {
            nodes.remove(&from);
            if nodes.is_empty() {
                unacknowledged.remove(&agent);
            }
        }
        drop(unacknowledged);
        {
            let mut refusing = self.refusing.lock().expect("the refusing nodes");
            let nodes = refusing.entry(agent).or_default();
            if runs {
                nodes.remove(&from);
            } else {
                nodes.insert(from);
            }
        }
        if let Some(waiting) = self
            .capable
            .lock()
            .expect("the capability waits")
            .remove(&(agent, from))
        {
            let _ = waiting.try_send(runs);
        }
        self.acknowledged.notify(usize::MAX);
    }

    /// Send where `agent` runs, with its record, to every other node, and
    /// keep sending it until each acknowledges it.
    pub(crate) fn announce(&self, agent: AgentId) {
        let Some(known) = self
            .directory
            .lock()
            .expect("the directory")
            .get(&agent)
            .cloned()
        else {
            return;
        };
        let others: std::collections::BTreeSet<NodeNumber> = self
            .space
            .as_ref()
            .map(|space| space.numbers())
            .unwrap_or_default()
            .into_iter()
            .filter(|node| *node != self.number)
            .collect();
        if others.is_empty() {
            return;
        }
        let order = known.placement.order();
        let message = PeerMessage::Directory {
            record: known.record,
            placement: known.placement,
        };
        for node in &others {
            self.send(*node, Class::Requests, &message);
        }
        self.unacknowledged
            .lock()
            .expect("the unacknowledged records")
            .insert(agent, (order, others));
    }

    /// Whether `node` could run `agent`'s program, as it answers when sent
    /// where the agent runs: false when it does not answer in `within`.
    pub(crate) async fn could_run(
        &self,
        agent: AgentId,
        node: NodeNumber,
        within: Duration,
    ) -> bool {
        let Some(known) = self
            .directory
            .lock()
            .expect("the directory")
            .get(&agent)
            .cloned()
        else {
            return false;
        };
        let (answer, answered) = smol::channel::bounded(1);
        self.capable
            .lock()
            .expect("the capability waits")
            .insert((agent, node), answer);
        let message = PeerMessage::Directory {
            record: known.record,
            placement: known.placement,
        };
        let until = Instant::now() + within;
        let runs = loop {
            self.send(node, Class::Requests, &message);
            let heard = async { answered.recv().await.ok() };
            let quiet = async {
                smol::Timer::after(RESEND.min(until.saturating_duration_since(Instant::now())))
                    .await;
                None
            };
            if let Some(runs) = heard.or(quiet).await {
                break runs;
            }
            if Instant::now() >= until {
                break false;
            }
        };
        self.capable
            .lock()
            .expect("the capability waits")
            .remove(&(agent, node));
        runs
    }

    /// Wait until a majority of `record`'s replicas hold it durably: false
    /// when they do not within [`MAJORITY`].
    pub(crate) async fn held_by_majority(&self, record: &CreationRecord) -> bool {
        let needed = record.replicas.len() / 2 + 1;
        let until = Instant::now() + MAJORITY;
        loop {
            let acknowledged = self.acknowledged.listen();
            let holding = {
                let unacknowledged = self
                    .unacknowledged
                    .lock()
                    .expect("the unacknowledged records");
                let waiting = unacknowledged.get(&record.agent).map(|(_, nodes)| nodes);
                let refusing = self.refusing.lock().expect("the refusing nodes");
                let refusing = refusing.get(&record.agent);
                // A replica counts once it holds the record and could run
                // the agent's program.
                record
                    .replicas
                    .iter()
                    .filter(|replica| {
                        **replica == self.number
                            || (!waiting.is_some_and(|nodes| nodes.contains(replica))
                                && !refusing.is_some_and(|nodes| nodes.contains(replica)))
                    })
                    .count()
            };
            if holding >= needed {
                return true;
            }
            if Instant::now() >= until {
                return false;
            }
            acknowledged
                .or(async {
                    smol::Timer::at(until).await;
                })
                .await;
        }
    }
}
